# Shared by run.sh and the attack scripts (source ../../lib.sh first).
source "$HERE/../common.sh"

category_name() {
  case "$1" in 0) echo none ;; 1) echo low ;; 2) echo "review suggested" ;; *) echo "?" ;; esac
}
