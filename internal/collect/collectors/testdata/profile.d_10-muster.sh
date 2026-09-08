# synthetic drop-in with a conditional umask
if [ "$UID" -ge 1000 ]; then
    umask 002
fi
