#!/bin/bash

echo "=== 1. Removing Copilot Worktrees ==="
# ลบ Worktree ทั้งหมด ยกเว้นโฟลเดอร์ปัจจุบันที่กำลังทำงานอยู่
for wt in $(git worktree list --porcelain | grep "^worktree " | awk '{print $2}'); do
    if [ "$wt" != "$PWD" ]; then
        echo "Removing worktree: $wt"
        git worktree remove -f "$wt"
    fi
done

# ล้าง Metadata ของ Worktree ที่ค้างอยู่ในระบบ Git
git worktree prune
echo "Worktrees cleaned successfully!"
echo ""

echo "=== 2. Removing Copilot Branches ==="
# กวาดลบ Local Branch ทั้งหมดที่ขึ้นต้นด้วย copilot/
for branch in $(git branch --format="%(refname:short)" | grep "^copilot/"); do
    echo "Deleting branch: $branch"
    git branch -D "$branch"
done
echo "Branches cleaned successfully!"
echo ""

echo "=== Current Git Status ==="
git worktree list
echo "--------------------------"
git branch

