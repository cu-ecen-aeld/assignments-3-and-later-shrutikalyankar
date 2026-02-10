#!/bin/sh
# Tester script for assignment 4
# Runs correctly from /usr/bin with PATH-based executables

set -e
set -u

OUTPUT_FILE=/tmp/assignment4-result.txt
CONF_DIR=/etc/finder-app/conf

NUMFILES=10
WRITESTR=AELD_IS_FUN
WRITEDIR=/tmp/aeld-data

USERNAME=$(cat ${CONF_DIR}/username.txt)
ASSIGNMENT=$(cat ${CONF_DIR}/assignment.txt)

if [ $# -ge 1 ]; then
    NUMFILES=$1
fi

if [ $# -ge 2 ]; then
    WRITESTR=$2
fi

if [ $# -ge 3 ]; then
    WRITEDIR=/tmp/aeld-data/$3
fi

MATCHSTR="The number of files are ${NUMFILES} and the number of matching lines are ${NUMFILES}"

echo "Writing ${NUMFILES} files containing string ${WRITESTR} to ${WRITEDIR}"

rm -rf "${WRITEDIR}"

if [ "${ASSIGNMENT}" != "assignment1" ]; then
    mkdir -p "${WRITEDIR}"
fi

for i in $(seq 1 ${NUMFILES}); do
    writer "${WRITEDIR}/${USERNAME}${i}.txt" "${WRITESTR}"
done

# Run finder and capture output
finder.sh "${WRITEDIR}" "${WRITESTR}" > "${OUTPUT_FILE}"

# Verify output
if grep -q "${MATCHSTR}" "${OUTPUT_FILE}"; then
    echo "success"
    exit 0
else
    echo "failed: expected '${MATCHSTR}'"
    echo "actual output:"
    cat "${OUTPUT_FILE}"
    exit 1
fi
