import re

with open('app/api/routes/abdm.py', 'r', encoding='utf-8') as f:
    text = f.read()

# Pattern to find all decorator blocks before 'async def'
pattern = r'((?:@router\.(?:get|post|put|patch|delete)\([\s\S]*?\)\s*)+)(async def [a-zA-Z0-9_]+)'

def clean_block(match):
    decs_text = match.group(1)
    func_sig = match.group(2)
    
    # Split individual @router calls
    decs = re.findall(r'@router\.(?:get|post|put|patch|delete)\([\s\S]*?\)\n', decs_text)
    if not decs:
        # try without trailing newline
        decs = [decs_text]
        
    kept_decs = []
    has_abha_v3 = any('/abha/v3/' in d for d in decs)
    
    for d in decs:
        # If an /abha/v3/ path exists in the block, drop the non-abha /v3/ duplicate
        if has_abha_v3 and re.search(r'@router\.(?:get|post|put|patch|delete)\(\s*["\']/v3/', d):
            print(f"Removing duplicate decorator for {func_sig}:\n{d.strip()}")
            continue
        # Also clean care_contexts_discover extra paths if care-contexts/discover exists
        if 'care_contexts_discover' in func_sig and ('/hiecm/' in d or '/v3/hip/' in d):
            print(f"Removing duplicate discover decorator:\n{d.strip()}")
            continue
        kept_decs.append(d)
        
    return "".join(kept_decs) + func_sig

cleaned_text = re.sub(pattern, clean_block, text)

with open('app/api/routes/abdm.py', 'w', encoding='utf-8') as f:
    f.write(cleaned_text)

print("Done cleaning duplicate decorators!")
