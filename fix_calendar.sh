#!/bin/bash
sed -i 's/React.isValidElement(child)/React.isValidElement<any>(child)/g' dashboard-v2/src/components/filesystem/Calendar.tsx
