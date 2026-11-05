package tunnel

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"

	"github.com/flynn/noise"
)

const (
	maxPayload = 16 * 1024
	maxRecord  = 1 + maxPayload + 16 // record type, payload, authentication tag
)

const (
	recordData byte = iota
	recordEOF
	recordRequest
	recordResponse
)

// Frames use a two-byte network-order length. Their limit is checked before
// reading a body, including during the handshake. Stream record types and EOF
// are encrypted, so the relay cannot forge a successful half-close.
func readFrame(r io.Reader, buffer []byte) ([]byte, error) {
	var header [2]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint16(header[:]))
	if n == 0 || n > len(buffer) {
		return nil, errors.New("tunnel: invalid frame length")
	}
	_, err := io.ReadFull(r, buffer[:n])
	return buffer[:n], err
}

func writeAll(w io.Writer, p []byte) error {
	for len(p) != 0 {
		n, err := w.Write(p)
		if n < 0 || n > len(p) {
			return errors.New("tunnel: invalid write count")
		}
		p = p[n:]
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrNoProgress
		}
	}
	return nil
}

func writeFrame(w io.Writer, message []byte) error {
	if len(message) == 0 || len(message) > 65535 {
		return errors.New("tunnel: invalid outgoing frame length")
	}
	var header [2]byte
	binary.BigEndian.PutUint16(header[:], uint16(len(message)))
	if err := writeAll(w, header[:]); err != nil {
		return err
	}
	return writeAll(w, message)
}

type secureConn struct {
	net.Conn
	send, receive   *noise.CipherState
	readMu, writeMu sync.Mutex
	readBuffer      []byte
	writeBuffer     []byte
	plaintext       []byte
	pending         []byte
	readErr         error
	writeErr        error
	writeClosed     bool
	stop            func() bool
}

func newSecureConn(raw net.Conn, send, receive *noise.CipherState) *secureConn {
	return &secureConn{
		Conn: raw, send: send, receive: receive,
		readBuffer:  make([]byte, maxRecord),
		writeBuffer: make([]byte, 0, maxRecord),
		plaintext:   make([]byte, 1+maxPayload),
	}
}

// readRecord is called with readMu held after setup. A frame failure is fatal:
// retrying could lose framing or roll the cipher nonce state out of sync.
func (c *secureConn) readRecord() ([]byte, error) {
	message, err := readFrame(c.Conn, c.readBuffer)
	if err == io.EOF {
		err = io.ErrUnexpectedEOF // only an authenticated EOF closes a direction
	}
	if err == nil {
		message, err = c.receive.Decrypt(message[:0], nil, message)
	}
	if err == nil && len(message) == 0 {
		err = errors.New("tunnel: empty secure record")
	}
	if err != nil {
		c.Close()
		return nil, err
	}
	return message, nil
}

func (c *secureConn) Read(p []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	if len(p) == 0 {
		return 0, nil
	}
	if len(c.pending) > 0 {
		n := copy(p, c.pending)
		c.pending = c.pending[n:]
		return n, nil
	}
	if c.readErr != nil {
		return 0, c.readErr
	}
	record, err := c.readRecord()
	if err == nil {
		switch record[0] {
		case recordData:
			if len(record) == 1 {
				err = errors.New("tunnel: empty data record")
			} else {
				c.pending = record[1:]
				n := copy(p, c.pending)
				c.pending = c.pending[n:]
				return n, nil
			}
		case recordEOF:
			if len(record) == 1 {
				err = io.EOF
			} else {
				err = errors.New("tunnel: malformed EOF record")
			}
		default:
			err = errors.New("tunnel: unexpected secure record")
		}
	}
	c.readErr = err
	if err != io.EOF {
		c.Close()
	}
	return 0, err
}

// writeRecordLocked reuses buffers and serializes each direction's Noise nonce.
func (c *secureConn) writeRecordLocked(kind byte, payload []byte) error {
	if c.writeErr != nil {
		return c.writeErr
	}
	if c.writeClosed {
		return net.ErrClosed
	}
	if len(payload) > maxPayload {
		return errors.New("tunnel: record payload too large")
	}
	c.plaintext[0] = kind
	copy(c.plaintext[1:], payload)
	message, err := c.send.Encrypt(c.writeBuffer[:0], nil, c.plaintext[:1+len(payload)])
	if err == nil {
		err = writeFrame(c.Conn, message)
	}
	if err != nil {
		c.writeErr = err
		c.Close()
	}
	return err
}

func (c *secureConn) writeRecord(kind byte, payload []byte) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	return c.writeRecordLocked(kind, payload)
}

func (c *secureConn) Write(p []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if c.writeClosed {
		return 0, net.ErrClosed
	}
	written := 0
	for len(p) > 0 {
		n := min(len(p), maxPayload)
		if err := c.writeRecordLocked(recordData, p[:n]); err != nil {
			return written, err
		}
		written += n
		p = p[n:]
	}
	return written, c.writeErr
}

// CloseWrite sends an authenticated EOF while leaving reads available.
func (c *secureConn) CloseWrite() error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if c.writeClosed {
		return c.writeErr
	}
	err := c.writeRecordLocked(recordEOF, nil)
	c.writeClosed = true
	return err
}

func (c *secureConn) Close() error {
	if c.stop != nil {
		c.stop()
	}
	return c.Conn.Close()
}
