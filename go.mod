module go.containerssh.io/libcontainerssh

go 1.21

toolchain go1.22.2

replace github.com/containerssh/gokrb5/v8 => /opt/workspaces/gokrb5/v8

require (
	dario.cat/mergo v1.0.0
	github.com/ScaleFT/sshkeys v1.2.0
	github.com/aws/aws-sdk-go v1.51.14
	github.com/containerd/console v1.0.4
	github.com/containerssh/gokrb5/v8 v8.0.0-00010101000000-000000000000
	github.com/creack/pty v1.1.21
	github.com/creasty/defaults v1.7.0
	github.com/docker/distribution v2.8.3+incompatible
	github.com/docker/docker v26.0.0+incompatible
	github.com/docker/go-connections v0.5.0
	github.com/fxamacker/cbor v1.5.1
	github.com/fxamacker/cbor/v2 v2.6.0
	github.com/glebarez/sqlite v1.11.0
	github.com/gliderlabs/ssh v0.3.7
	github.com/google/go-cmp v0.6.0
	github.com/google/go-containerregistry v0.13.0
	github.com/google/uuid v1.6.0
	github.com/gorilla/schema v1.3.0
	github.com/gravitational/trace v1.4.0
	github.com/json-iterator/go v1.1.12
	github.com/mattn/go-shellwords v1.0.12
	github.com/mholt/archiver/v3 v3.5.1
	github.com/mikesmitty/edkey v0.0.0-20170222072505-3356ea4e686a
	github.com/mitchellh/mapstructure v1.5.0
	github.com/msteinert/pam/v2 v2.0.0
	github.com/opencontainers/image-spec v1.1.0
	github.com/opencontainers/runc v1.1.12
	github.com/oschwald/geoip2-golang v1.9.0
	github.com/pkg/sftp v1.13.6
	github.com/qdm12/reprint v0.0.0-20200326205758-722754a53494
	github.com/stretchr/testify v1.9.0
	golang.org/x/crypto v0.21.0
	golang.org/x/sys v0.18.0
	golang.org/x/term v0.18.0
	gopkg.in/jcmturner/goidentity.v3 v3.0.0
	gopkg.in/yaml.v3 v3.0.1
	gorm.io/gorm v1.25.9
	k8s.io/api v0.29.3
	k8s.io/apimachinery v0.29.3
	k8s.io/client-go v0.29.3
	sigs.k8s.io/kind v0.22.0
	sigs.k8s.io/yaml v1.4.0
)

require (
	github.com/Azure/go-ansiterm v0.0.0-20230124172434-306776ec8161 // indirect
	github.com/BurntSushi/toml v1.2.1 // indirect
	github.com/Microsoft/go-winio v0.6.1 // indirect
	github.com/alessio/shellescape v1.4.1 // indirect
	github.com/andybalholm/brotli v1.0.4 // indirect
	github.com/anmitsu/go-shlex v0.0.0-20200514113438-38f4b401e2be // indirect
	github.com/containerd/stargz-snapshotter/estargz v0.14.3 // indirect
	github.com/cyphar/filepath-securejoin v0.2.4 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/dchest/bcrypt_pbkdf v0.0.0-20150205184540-83f37f9c154a // indirect
	github.com/distribution/reference v0.5.0 // indirect
	github.com/docker/cli v24.0.0+incompatible // indirect
	github.com/docker/docker-credential-helpers v0.7.0 // indirect
	github.com/docker/go-units v0.5.0 // indirect
	github.com/dsnet/compress v0.0.2-0.20210315054119-f66993602bf5 // indirect
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/emicklei/go-restful/v3 v3.11.0 // indirect
	github.com/evanphx/json-patch/v5 v5.6.0 // indirect
	github.com/glebarez/go-sqlite v1.21.2 // indirect
	github.com/go-logr/logr v1.4.1 // indirect
	github.com/go-openapi/jsonpointer v0.19.6 // indirect
	github.com/go-openapi/jsonreference v0.20.2 // indirect
	github.com/go-openapi/swag v0.22.3 // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/golang/protobuf v1.5.4 // indirect
	github.com/golang/snappy v0.0.4 // indirect
	github.com/google/gnostic-models v0.6.8 // indirect
	github.com/google/gofuzz v1.2.0 // indirect
	github.com/google/safetext v0.0.0-20220905092116-b49f7bc46da2 // indirect
	github.com/gorilla/websocket v1.5.0 // indirect
	github.com/hashicorp/go-uuid v1.0.2 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/jcmturner/aescts/v2 v2.0.0 // indirect
	github.com/jcmturner/dnsutils/v2 v2.0.0 // indirect
	github.com/jcmturner/gofork v1.0.0 // indirect
	github.com/jcmturner/goidentity/v6 v6.0.1 // indirect
	github.com/jcmturner/rpc/v2 v2.0.3 // indirect
	github.com/jinzhu/inflection v1.0.0 // indirect
	github.com/jinzhu/now v1.1.5 // indirect
	github.com/jmespath/go-jmespath v0.4.0 // indirect
	github.com/josharian/intern v1.0.0 // indirect
	github.com/klauspost/compress v1.16.5 // indirect
	github.com/klauspost/pgzip v1.2.5 // indirect
	github.com/kr/fs v0.1.0 // indirect
	github.com/mailru/easyjson v0.7.7 // indirect
	github.com/mattn/go-isatty v0.0.17 // indirect
	github.com/mitchellh/go-homedir v1.1.0 // indirect
	github.com/moby/spdystream v0.2.0 // indirect
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd // indirect
	github.com/modern-go/reflect2 v1.0.2 // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/mxk/go-flowrate v0.0.0-20140419014527-cca7078d478f // indirect
	github.com/nwaples/rardecode v1.1.0 // indirect
	github.com/opencontainers/go-digest v1.0.0 // indirect
	github.com/oschwald/maxminddb-golang v1.11.0 // indirect
	github.com/pelletier/go-toml v1.9.4 // indirect
	github.com/pierrec/lz4/v4 v4.1.15 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec // indirect
	github.com/sirupsen/logrus v1.9.3 // indirect
	github.com/spf13/cobra v1.7.0 // indirect
	github.com/spf13/pflag v1.0.5 // indirect
	github.com/ulikunitz/xz v0.5.9 // indirect
	github.com/vbatts/tar-split v0.11.3 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	github.com/xi2/xz v0.0.0-20171230120015-48954b6210f8 // indirect
	golang.org/x/mod v0.14.0 // indirect
	golang.org/x/net v0.21.0 // indirect
	golang.org/x/oauth2 v0.16.0 // indirect
	golang.org/x/sync v0.6.0 // indirect
	golang.org/x/text v0.14.0 // indirect
	golang.org/x/time v0.3.0 // indirect
	golang.org/x/tools v0.16.1 // indirect
	google.golang.org/appengine v1.6.8 // indirect
	google.golang.org/protobuf v1.33.0 // indirect
	gopkg.in/inf.v0 v0.9.1 // indirect
	gopkg.in/yaml.v2 v2.4.0 // indirect
	k8s.io/klog/v2 v2.110.1 // indirect
	k8s.io/kube-openapi v0.0.0-20231010175941-2dd684a91f00 // indirect
	k8s.io/utils v0.0.0-20230726121419-3b25d923346b // indirect
	modernc.org/libc v1.22.5 // indirect
	modernc.org/mathutil v1.5.0 // indirect
	modernc.org/memory v1.5.0 // indirect
	modernc.org/sqlite v1.23.1 // indirect
	sigs.k8s.io/json v0.0.0-20221116044647-bc3834ca7abd // indirect
	sigs.k8s.io/structured-merge-diff/v4 v4.4.1 // indirect
)

replace github.com/jcmturner/gokrb5 => /opt/workspaces/gokrb5
