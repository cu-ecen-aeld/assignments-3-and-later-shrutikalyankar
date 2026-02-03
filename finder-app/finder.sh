#!/bin/sh

if [ $# -lt 2 ]; then   
	echo "Error: arguments not present."
	echo "Usage: $0 <filesdir><searchstr>"
	exit 1
fi

filesdir="$1"
searchstr="$2"

#There was an error in this if condition. I asked chatgpt for help debugging. The issue was that there were extra spaces
if [ ! -d "$filesdir" ]; then
	echo "Error: $filesdir is not a directory."
	exit 1
fi

X=$(find "$filesdir" -type f | wc -l)
Y=$(grep -rhnF "$searchstr" "$filesdir" 2>/dev/null | wc -l)

echo "The number of files are $X and the number of matching lines are $Y."
