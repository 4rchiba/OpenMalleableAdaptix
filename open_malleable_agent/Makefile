all: clean
	@ echo "    * Building agent_openmalleable plugin"
	@ mkdir dist
	@ cp config.yaml ax_config.axs ./dist/
	@ GOWORK=off GOEXPERIMENT=jsonv2,greenteagc go build -buildmode=plugin -ldflags="-s -w" -o ./dist/agent_openmalleable.so pl_main.go pl_packer.go pl_utils.go pl_sideloading.go
	@ echo "      done..."

	@ echo "    * Building agent"
	@ (cd src_beacon && $(MAKE) --no-print-directory)
	@ (cd src_beacon && $(MAKE) --no-print-directory VARIANT_SUFFIX=_gpa EXTRA_CXXFLAGS=-DAPI_RESOLUTION_GETPROCADDRESS)
	@ (cd src_beacon && $(MAKE) --no-print-directory VARIANT_SUFFIX=_dfr EXTRA_CXXFLAGS=-DIAT_HIDING)
	@ mv src_beacon/objects_http ./dist/objects_http
	@ mv src_beacon/objects_smb ./dist/objects_smb
	@ mv src_beacon/objects_tcp ./dist/objects_tcp
	@ mv src_beacon/objects_dns ./dist/objects_dns
	@ mv src_beacon/objects_http_gpa ./dist/objects_http_gpa
	@ mv src_beacon/objects_smb_gpa ./dist/objects_smb_gpa
	@ mv src_beacon/objects_tcp_gpa ./dist/objects_tcp_gpa
	@ mv src_beacon/objects_dns_gpa ./dist/objects_dns_gpa
	@ mv src_beacon/objects_http_dfr ./dist/objects_http_dfr
	@ mv src_beacon/objects_smb_dfr ./dist/objects_smb_dfr
	@ mv src_beacon/objects_tcp_dfr ./dist/objects_tcp_dfr
	@ mv src_beacon/objects_dns_dfr ./dist/objects_dns_dfr
	@ echo "      done..."

clean:
	@ rm -rf dist
