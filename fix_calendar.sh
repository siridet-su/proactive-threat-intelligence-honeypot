#!/bin/bash
sed -i 's/child\.props/(child as React.ReactElement<any>).props/g' dashboard-v2/src/components/filesystem/Calendar.tsx
