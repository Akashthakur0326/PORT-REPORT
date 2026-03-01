import re

def validate_evidence(validation_rule, result):
    """
    Pure Logic Function. Judges the outcome of an exploit.
    """
    if result is None:
        return False
        
    rule_type = validation_rule.get("type")

    try:
        if rule_type == "regex":
            pattern = validation_rule.get("pattern")
            return re.search(pattern, str(result), re.IGNORECASE) is not None
        
        if rule_type == "status_code":
            expected = validation_rule.get("expected")
            return int(result) == int(expected)
            
        if rule_type == "body_contains":
            expected = validation_rule.get("expected")
            return expected in str(result)
        
        if rule_type == "exact_match":
            expected = validation_rule.get("expected")
            return str(result).strip() == str(expected).strip()
        
        if rule_type == "exact_match":
            return str(result).strip() == str(validation_rule.get("expected")).strip()
        
    except Exception as e:
        print(f"[!] Validation Logic Error: {e}")
        return False
        
    return False