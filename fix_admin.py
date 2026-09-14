with open('app.py', 'r', encoding='utf-8') as f:
    lines = f.readlines()

# Find line numbers of all occurrences of def admin_login
occurrences = []
for i, line in enumerate(lines):
    if 'def admin_login()' in line:
        occurrences.append(i)

print(f'Found def admin_login at lines: {occurrences}')

if len(occurrences) >= 2:
    # Keep only everything before the second occurrence
    # But go back a few lines to also remove the decorator above it
    cut_at = occurrences[1]
    # Walk back to remove blank lines and decorators before it
    while cut_at > 0 and lines[cut_at-1].strip() in ('', '@app.route(\'/admin/login\', methods=[\'GET\', \'POST\'])'):
        cut_at -= 1
    # Actually just cut at a safe point - 3 lines before
    cut_at = max(0, occurrences[1] - 5)
    cleaned = lines[:cut_at]
    with open('app.py', 'w', encoding='utf-8') as f:
        f.writelines(cleaned)
    print(f'SUCCESS: Removed duplicate from line {cut_at}. File cleaned.')
else:
    print('Only one occurrence found - no duplicates to remove.')