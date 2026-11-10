package bbr

import (
	"golang.org/x/exp/constraints"
)

// 实现 Kathleen Nichols 算法，用于跟踪固定时间区间内一系列样本的最小值（或最大值）
// 估计值（例如过去五分钟内的最小 RTT）。算法会跟踪最佳、次佳和第三佳的最小值（或最大值）
// 估计值，并保持不变量：第 n 佳估计值的测量时间不早于第 n-1 佳估计值。

// 算法的工作方式如下：重置时，三个估计值都设为同一个样本。随后在窗口的第二个四分位处
// 记录次佳估计值，并在窗口的后半段记录第三佳估计值；当窗口内的真实最小值单调递增
// （或真实最大值单调递减）时，这样可以限制最坏情况下的误差。
//
// 新的最佳样本会替换全部三个估计值，因为它比窗口中的其他样本都更低（或更高），且时间最新。
// 因此，每次出现新的最小值时，窗口实际上都会重置。次佳和第三佳估计值也遵循相同规律。
// 具体来说，如果新样本优于次佳估计值但不优于最佳估计值，它会替换次佳和第三佳估计值，
// 但不会替换最佳估计值。同理，如果样本优于第三佳估计值但不优于其他估计值，则只替换第三佳估计值。
//
// 最后，最佳估计值过期时由次佳估计值替代，次佳估计值再由第三佳估计值替代；最新样本则成为第三佳估计值。

type WindowedFilterValue interface {
	any
}

type WindowedFilterTime interface {
	constraints.Integer | constraints.Float
}

type WindowedFilter[V WindowedFilterValue, T WindowedFilterTime] struct {
	// 窗口的时间长度。
	windowLength T
	estimates    []entry[V, T]
	comparator   func(V, V) int
}

type entry[V WindowedFilterValue, T WindowedFilterTime] struct {
	sample V
	time   T
}

// 比较两个值；如果第一个值大于或等于第二个值，则返回 true。
func MaxFilter[O constraints.Ordered](a, b O) int {
	if a > b {
		return 1
	} else if a < b {
		return -1
	}
	return 0
}

// 比较两个值；如果第一个值小于或等于第二个值，则返回 true。
func MinFilter[O constraints.Ordered](a, b O) int {
	if a < b {
		return 1
	} else if a > b {
		return -1
	}
	return 0
}

func NewWindowedFilter[V WindowedFilterValue, T WindowedFilterTime](windowLength T, comparator func(V, V) int) *WindowedFilter[V, T] {
	return &WindowedFilter[V, T]{
		windowLength: windowLength,
		estimates:    make([]entry[V, T], 3, 3),
		comparator:   comparator,
	}
}

// 更改窗口长度，但不更新当前样本。
func (f *WindowedFilter[V, T]) SetWindowLength(windowLength T) {
	f.windowLength = windowLength
}

func (f *WindowedFilter[V, T]) GetBest() V {
	return f.estimates[0].sample
}

func (f *WindowedFilter[V, T]) GetSecondBest() V {
	return f.estimates[1].sample
}

func (f *WindowedFilter[V, T]) GetThirdBest() V {
	return f.estimates[2].sample
}

// 使用 |sample| 更新最佳估计值，并在必要时使过期估计值失效并更新估计值。
func (f *WindowedFilter[V, T]) Update(newSample V, newTime T) {
	// 如果估计值尚未初始化、新样本成为最佳值，或最新记录的估计值过旧，则重置所有估计值。
	if f.comparator(f.estimates[0].sample, *new(V)) == 0 ||
		f.comparator(newSample, f.estimates[0].sample) >= 0 ||
		newTime-f.estimates[2].time > f.windowLength {
		f.Reset(newSample, newTime)
		return
	}

	if f.comparator(newSample, f.estimates[1].sample) >= 0 {
		f.estimates[1] = entry[V, T]{newSample, newTime}
		f.estimates[2] = f.estimates[1]
	} else if f.comparator(newSample, f.estimates[2].sample) >= 0 {
		f.estimates[2] = entry[V, T]{newSample, newTime}
	}

	// 根据需要使估计值过期并更新。
	if newTime-f.estimates[0].time > f.windowLength {
		// 最佳估计值在整个窗口期间都未更新，因此将次佳和第三佳估计值依次提升。
		f.estimates[0] = f.estimates[1]
		f.estimates[1] = f.estimates[2]
		f.estimates[2] = entry[V, T]{newSample, newTime}
		// 需要再迭代一次。也要检查新的最佳估计值是否已超出窗口，因为它也可能是在很久以前记录的。
		// 无需再多迭代一次，因为方法开头已经处理了这种情况。
		if newTime-f.estimates[0].time > f.windowLength {
			f.estimates[0] = f.estimates[1]
			f.estimates[1] = f.estimates[2]
		}
		return
	}
	if f.comparator(f.estimates[1].sample, f.estimates[0].sample) == 0 &&
		newTime-f.estimates[1].time > f.windowLength/4 {
		// 窗口的四分之一时间内没有出现更好的样本，因此从窗口的第二个四分位中选取次佳估计值。
		f.estimates[1] = entry[V, T]{newSample, newTime}
		f.estimates[2] = f.estimates[1]
		return
	}

	if f.comparator(f.estimates[2].sample, f.estimates[1].sample) == 0 &&
		newTime-f.estimates[2].time > f.windowLength/2 {
		// 半个窗口过去仍未出现更好的估计值，因此从窗口后半段选取第三佳估计值。
		f.estimates[2] = entry[V, T]{newSample, newTime}
	}
}

// 将所有估计值重置为新样本。
func (f *WindowedFilter[V, T]) Reset(newSample V, newTime T) {
	f.estimates[2] = entry[V, T]{newSample, newTime}
	f.estimates[1] = f.estimates[2]
	f.estimates[0] = f.estimates[1]
}

func (f *WindowedFilter[V, T]) Clear() {
	f.estimates = make([]entry[V, T], 3, 3)
}
