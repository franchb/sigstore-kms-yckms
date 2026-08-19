FROM gcr.io/oss-fuzz-base/base-builder-go@sha256:e5e5ecf4fb18a2f47bf0462c37e35728e8f6023ee4b7ff8bc5f903e6acba46da
COPY . $SRC/sigstore-kms-yckms
WORKDIR $SRC/sigstore-kms-yckms
COPY .clusterfuzzlite/build.sh $SRC/
ENV GOTOOLCHAIN=auto
