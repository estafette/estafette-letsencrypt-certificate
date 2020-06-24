module github.com/estafette/estafette-letsencrypt-certificate

go 1.12

require (
	github.com/alecthomas/kingpin v2.2.6+incompatible
	github.com/estafette/estafette-foundation v0.0.57
	github.com/go-acme/lego/v3 v3.4.0
	github.com/prometheus/client_golang v1.1.0
	github.com/rs/zerolog v1.17.2
	github.com/stretchr/testify v1.4.0
	k8s.io/api v0.17.0
	k8s.io/apimachinery v0.17.0
	k8s.io/client-go v0.17.0
	k8s.io/utils v0.0.0-20200619165400-6e3d28b6ed19 // indirect
)
