#!/usr/bin/env bash
set -euo pipefail
A=$(cd "$(dirname "$0")" && pwd)
R=$(cd "$A/.." && pwd)

: "${ANDROID_HOME:?ANDROID_HOME is not set}"
: "${KEYSTORE:?KEYSTORE is not set}"
: "${KEYSTORE_PASS:?KEYSTORE_PASS is not set}"
KEY_ALIAS=${KEY_ALIAS:-volfram}
BT=${BUILD_TOOLS:-$(ls -d "$ANDROID_HOME"/build-tools/* | sort -V | tail -1)}
JAR=${ANDROID_JAR:-$ANDROID_HOME/platforms/android-35/android.jar}
VER=${VER:-1.0.8}
CODE=${CODE:-9}

L=$A/libs/arm64-v8a
for f in libsingbox.so libxray.so libtun2socks.so; do
  [ -f "$L/$f" ] || { echo "missing $L/$f, run scripts/fetch-cores.sh" >&2; exit 1; }
done

W=$A/build
rm -rf "$W"
mkdir -p "$W/gen" "$W/classes" "$W/dex" "$W/apk/lib/arm64-v8a"

(cd "$R" && GOOS=android GOARCH=arm64 CGO_ENABLED=0 go build -tags volframandroid -trimpath -ldflags "-s -w" -o "$W/apk/lib/arm64-v8a/libvolfram.so" .)
cp "$L"/libsingbox.so "$L"/libxray.so "$L"/libtun2socks.so "$W/apk/lib/arm64-v8a/"

"$BT/aapt2" compile --dir "$A/app/res" -o "$W/res.zip"
"$BT/aapt2" link -I "$JAR" --manifest "$A/app/AndroidManifest.xml" -o "$W/base.apk" --java "$W/gen" \
  --min-sdk-version 24 --target-sdk-version 34 --version-code "$CODE" --version-name "$VER" --replace-version "$W/res.zip"

javac -nowarn -Xlint:-options -source 8 -target 8 -encoding UTF-8 -bootclasspath "$JAR:$BT/core-lambda-stubs.jar" -d "$W/classes" \
  $(find "$A/app/src" "$W/gen" -name '*.java')
"$BT/d8" --release --min-api 24 --lib "$JAR" --output "$W/dex" $(find "$W/classes" -name '*.class')

cp "$W/dex/classes.dex" "$W/apk/"
(cd "$W/apk" && zip -q -r ../base.apk classes.dex lib)
"$BT/zipalign" -p -f 4 "$W/base.apk" "$W/aligned.apk"

if [ ! -f "$KEYSTORE" ]; then
  keytool -genkeypair -keystore "$KEYSTORE" -storepass:env KEYSTORE_PASS -keypass:env KEYSTORE_PASS -alias "$KEY_ALIAS" \
    -keyalg RSA -keysize 3072 -validity 12000 -dname "CN=Volfram" >/dev/null
fi

mkdir -p "$R/dist"
"$BT/apksigner" sign --ks "$KEYSTORE" --ks-pass env:KEYSTORE_PASS --ks-key-alias "$KEY_ALIAS" --out "$R/dist/Volfram.apk" "$W/aligned.apk"
"$BT/apksigner" verify "$R/dist/Volfram.apk"
ls -la "$R/dist/Volfram.apk"
