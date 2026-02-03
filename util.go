package main

import (
	"io"
	"net"
	"sync"
	"time"
)

/* The buffer (64KB) is used after successful authentication between the connections. */
const ConnectionBuffer = 64 * 1024

/* Strongly-typed buffer pool wrappers to eliminate type assertion overhead. */
type bufferPool struct {
	pool sync.Pool
	size int
}

func newBufferPool(size int) *bufferPool {
	return &bufferPool{
		pool: sync.Pool{
			New: func() interface{} {
				return make([]byte, size)
			},
		},
		size: size,
	}
}

func (p *bufferPool) Get() []byte {
	v := p.pool.Get()
	if v == nil {
		return make([]byte, p.size)
	}
	vBytes := v.([]byte)
	return vBytes
}

func (p *bufferPool) Put(buf []byte) {
	if cap(buf) == p.size {
		p.pool.Put(buf)
	}
}

var bytePool = newBufferPool(ConnectionBuffer)

/* Transfer copies data from src to dst with a timeout policy. Returns copied bytes. */
func Transfer(dst net.Conn, src net.Conn) (int64, error) {
	buf := bytePool.Get()
	defer bytePool.Put(buf)

	var written int64

	const deadlineInterval = 30 * time.Second
	const idleTimeout = 5 * time.Minute

	/* Set initial deadline immediately to prevent infinite wait. */
	_ = src.SetReadDeadline(time.Now().Add(idleTimeout))
	_ = dst.SetWriteDeadline(time.Now().Add(idleTimeout))
	lastDeadlineUpdate := time.Now()

	for {
		/* Refresh deadline less frequently. */
		if time.Since(lastDeadlineUpdate) > deadlineInterval {
			_ = src.SetReadDeadline(time.Now().Add(idleTimeout))
			_ = dst.SetWriteDeadline(time.Now().Add(idleTimeout))
			lastDeadlineUpdate = time.Now()
		}

		n, err := src.Read(buf)
		if n > 0 {
			/* Write all bytes with retry loop to handle short writes. */
			offset := 0
			for offset < n {
				nw, wErr := dst.Write(buf[offset:n])
				if wErr != nil {
					return written, wErr
				} else if nw > 0 {
					written += int64(nw)
					offset += nw
				} else if nw == 0 {
					/* Zero write without error is unusual, treat as stall. */
					return written, io.ErrShortWrite
				}
			}
		}

		if err != nil {
			if err == io.EOF {
				return written, nil
			}
			return written, err
		}
	}
}
