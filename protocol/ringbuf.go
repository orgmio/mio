package protocol

import "sync"

const (
	ringInitCap     = 32 << 10  // 32 KiB
	ringRetainedCap = 256 << 10 // 256 KiB: 空闲流最多保留的容量，超出部分归还缓冲池
	ringPoolMaxCap  = 1 << 20   // 1 MiB
)

var (
	pool64K  = sync.Pool{New: func() any { b := make([]byte, 64<<10); return &b }}
	pool256K = sync.Pool{New: func() any { b := make([]byte, 256<<10); return &b }}
	pool1M   = sync.Pool{New: func() any { b := make([]byte, 1<<20); return &b }}
)

func getRingBuf(minCap int) []byte {
	switch {
	case minCap <= 64<<10:
		return (*pool64K.Get().(*[]byte))[:64<<10]
	case minCap <= 256<<10:
		return (*pool256K.Get().(*[]byte))[:256<<10]
	case minCap <= 1<<20:
		return (*pool1M.Get().(*[]byte))[:1<<20]
	default:
		return make([]byte, minCap)
	}
}

func putRingBuf(b []byte) {
	c := cap(b)
	switch c {
	case 64 << 10:
		b = b[:c]
		pool64K.Put(&b)
	case 256 << 10:
		b = b[:c]
		pool256K.Put(&b)
	case 1 << 20:
		b = b[:c]
		pool1M.Put(&b)
	}
}

// ringBuffer 是流接收端使用的环形字节缓冲，避免 bytes.Buffer 反复丢弃与搬移内存。
type ringBuffer struct {
	buf  []byte
	head int
	size int
}

func (r *ringBuffer) Len() int { return r.size }
func (r *ringBuffer) Cap() int { return len(r.buf) }

func (r *ringBuffer) grow(need int) {
	target := max(ringInitCap, len(r.buf)*2, r.size+need)
	// 对齐到池化档位，减少额外分配与碎片。
	switch {
	case target <= 64<<10:
		target = 64 << 10
	case target <= 256<<10:
		target = 256 << 10
	case target <= 1<<20:
		target = 1 << 20
	}
	next := getRingBuf(target)
	if r.size > 0 {
		s1, s2 := r.slices()
		n := copy(next, s1)
		copy(next[n:], s2)
	}
	if r.buf != nil {
		putRingBuf(r.buf)
	}
	r.buf = next
	r.head = 0
}

func (r *ringBuffer) Write(p []byte) {
	if len(p) == 0 {
		return
	}
	if r.size+len(p) > len(r.buf) {
		r.grow(len(p))
	}
	tail := r.head + r.size
	if tail >= len(r.buf) {
		tail -= len(r.buf)
	}
	first := min(len(p), len(r.buf)-tail)
	copy(r.buf[tail:], p[:first])
	if first < len(p) {
		copy(r.buf, p[first:])
	}
	r.size += len(p)
}

func (r *ringBuffer) Read(p []byte) int {
	n := min(len(p), r.size)
	if n == 0 {
		return 0
	}
	first := min(n, len(r.buf)-r.head)
	copy(p, r.buf[r.head:r.head+first])
	if first < n {
		copy(p[first:], r.buf[:n-first])
	}
	r.consume(n)
	return n
}

func (r *ringBuffer) slices() (s1, s2 []byte) {
	if r.size == 0 {
		return nil, nil
	}
	first := min(r.size, len(r.buf)-r.head)
	s1 = r.buf[r.head : r.head+first]
	if first < r.size {
		s2 = r.buf[:r.size-first]
	}
	return s1, s2
}

func (r *ringBuffer) consume(n int) {
	if n <= 0 {
		return
	}
	if n >= r.size {
		r.head = 0
		r.size = 0
		return
	}
	r.head += n
	if r.head >= len(r.buf) {
		r.head -= len(r.buf)
	}
	r.size -= n
}

func (r *ringBuffer) maybeShrink(closing bool) {
	if r.size == 0 && r.buf != nil && (closing || len(r.buf) > ringRetainedCap) {
		putRingBuf(r.buf)
		r.buf = nil
		r.head = 0
	}
}

func (r *ringBuffer) release() {
	if r.buf != nil {
		putRingBuf(r.buf)
		r.buf = nil
	}
	r.head = 0
	r.size = 0
}
