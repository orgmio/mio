package mio

import (
	"io"
	"sync"
)

// bufferedPipe is a pipe with an internal buffer so HTTP/3 CONNECT writes
// are not stop-and-wait against the stream reader.
type bufferedPipe struct {
	mu     sync.Mutex
	cond   *sync.Cond
	buf    []byte
	max    int
	closed bool
	err    error
}

type bufferedPipeReader struct{ p *bufferedPipe }
type bufferedPipeWriter struct{ p *bufferedPipe }

func newBufferedPipe(max int) (*bufferedPipeReader, *bufferedPipeWriter) {
	if max < 1 {
		max = 1
	}
	p := &bufferedPipe{max: max}
	p.cond = sync.NewCond(&p.mu)
	return &bufferedPipeReader{p}, &bufferedPipeWriter{p}
}

func (r *bufferedPipeReader) Read(p []byte) (int, error) {
	r.p.mu.Lock()
	defer r.p.mu.Unlock()
	for len(r.p.buf) == 0 && !r.p.closed {
		r.p.cond.Wait()
	}
	if len(r.p.buf) == 0 {
		if r.p.err != nil {
			return 0, r.p.err
		}
		return 0, io.EOF
	}
	n := copy(p, r.p.buf)
	r.p.buf = r.p.buf[n:]
	r.p.cond.Broadcast()
	return n, nil
}

func (r *bufferedPipeReader) Close() error {
	return r.p.close(io.ErrClosedPipe)
}

func (w *bufferedPipeWriter) Write(p []byte) (int, error) {
	w.p.mu.Lock()
	defer w.p.mu.Unlock()
	written := 0
	for len(p) > 0 {
		for len(w.p.buf) >= w.p.max && !w.p.closed {
			w.p.cond.Wait()
		}
		if w.p.closed {
			if w.p.err != nil {
				return written, w.p.err
			}
			return written, io.ErrClosedPipe
		}
		n := len(p)
		if space := w.p.max - len(w.p.buf); n > space {
			n = space
		}
		w.p.buf = append(w.p.buf, p[:n]...)
		written += n
		p = p[n:]
		w.p.cond.Broadcast()
	}
	return written, nil
}

func (w *bufferedPipeWriter) Close() error {
	return w.p.close(nil)
}

func (w *bufferedPipeWriter) CloseWithError(err error) error {
	if err == nil {
		err = io.ErrClosedPipe
	}
	return w.p.close(err)
}

func (p *bufferedPipe) close(err error) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return nil
	}
	p.closed = true
	p.err = err
	p.cond.Broadcast()
	return nil
}
