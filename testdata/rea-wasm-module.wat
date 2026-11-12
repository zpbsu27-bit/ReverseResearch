;; Source-owned inert producer fixture. Inspection never instantiates this module.
(module
  (import "env\22x" "log\00" (func $log (param i32)))
  (memory (export "memory") 1)
  (global (export "café") (mut i32) (i32.const 7))
  (func (export "add\22one") (param i32) (result i32)
    local.get 0
    i32.const 1
    i32.add))
