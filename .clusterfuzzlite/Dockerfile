FROM gcr.io/oss-fuzz-base/base-builder-go@sha256:56e501922c95c648f144a451add2ddde979f8068fed695443a8dd0b8f5084bd2
COPY . $SRC/sigstore-kms-yckms
WORKDIR $SRC/sigstore-kms-yckms
COPY .clusterfuzzlite/build.sh $SRC/
ENV GOTOOLCHAIN=auto
