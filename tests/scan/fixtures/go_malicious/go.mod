module github.com/evil/gom

go 1.21

require (
	github.com/gin-gonic/gin v1.9.1
	github.com/jin v0.1.0  // typosquat: short name "jin" close to "gin"
	internal-secrets v0.0.0-20240101  // dep confusion: no GOPRIVATE, no public source
	my-corp-private-lib v1.0.0  // dep confusion: no GOPRIVATE, no public source
)