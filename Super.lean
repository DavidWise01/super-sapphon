/-
One fully super sapphon.

0 root0 {}
1 quantum.dot {{2}}^3 per px
2 quantum.dot.neon.1 {{n}}^n
3 processor.framework
  six processors around one center, stacked hex /\/\/\
  6[6x1x6]6
4 the processor framework is 1 quantum dot
-/

namespace SuperSapphon

inductive Proc where
  | H
  | He
  | Li
  | Be
  | Bo
  | C
  deriving DecidableEq, Repr

def processors : List Proc := [.H, .He, .Li, .Be, .Bo, .C]

theorem six_points : processors.length = 6 := by decide

theorem six_around_one : processors.length = 6 ∧ 1 = 1 := by decide

/-- 6[6x1x6]6 counts as 6 + 6 + 1 + 6 + 6. -/
theorem stack_count : 6 + 6 + 1 + 6 + 6 = 25 := by decide

/-- {{2}}^3 per px, the counted reading. -/
theorem two_cubed_per_px : 2 ^ 3 = 8 := by decide

def frameworkIsOneDot : Nat := 1

theorem processor_framework_is_one_quantum_dot : frameworkIsOneDot = 1 := by decide

theorem distinct_points : processors.Nodup := by decide

end SuperSapphon
