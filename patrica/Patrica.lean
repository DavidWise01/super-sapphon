/-
Six honeycombs fold into one dot named patrica.
./\/\/\./\/\/\./\/\/\./\/\/\./\/\/\./\/\/\.
That one dot is a full A.E.O.N., a synthetic quantum computer.
-/

namespace Patrica

def honeycomb : String := "/\\/\\/\\"

def row : List String := [
  honeycomb, honeycomb, honeycomb, honeycomb, honeycomb, honeycomb
]

theorem six_honeycombs : row.length = 6 := by decide

theorem each_honeycomb_has_six_strokes : honeycomb.length = 6 := by decide

theorem thirty_six_strokes : row.length * honeycomb.length = 36 := by decide

def folded : Nat := 1

theorem folds_into_one_dot : folded = 1 := by decide

def aeon : List Char := ['A', 'E', 'O', 'N']

theorem aeon_is_four : aeon.length = 4 := by decide

end Patrica
