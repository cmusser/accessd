# This script takes care of building your crate and packaging it for release

set -ex

main() {
    local src=$(pwd) \
          stage=

    case $TRAVIS_OS_NAME in
        linux)
            stage=$(mktemp -d)
            ;;
        osx)
            stage=$(mktemp -d -t tmp)
            ;;
    esac

    test -f Cargo.lock || cargo generate-lockfile

    cross rustc --bin access --target $TARGET --release -- -C lto
    cross rustc --bin accessd --target $TARGET --release -- -C lto
    cross rustc --bin access-keygen --target $TARGET --release -- -C lto

    cp target/$TARGET/release/access $stage/
    cp target/$TARGET/release/accessd $stage/
    cp target/$TARGET/release/access-keygen $stage/

    cd $stage
    tar czf $src/$CRATE_NAME-$TRAVIS_TAG-$TARGET.tar.gz *
    cd $src

    rm -rf $stage
}

main
