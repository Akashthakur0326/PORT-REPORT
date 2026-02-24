import re

def validate_evidence(validation_rule, result):
    """
    Pure Logic Function.
    Inputs:
      validation_rule (dict): The rule from the DB (e.g., {"type": "regex", "pattern": "..."})
      result (str/int/dict): The raw response from the victim.
    Returns:
      bool: True if vulnerable, False otherwise.
    """
    if result is None:
        return False
        
    rule_type = validation_rule.get("type")

    try:
        # Regex Match (for shell outputs, banners)
        if rule_type == "regex":
            pattern = validation_rule.get("pattern")
            # Convert result to string just in case
            return re.search(pattern, str(result), re.IGNORECASE) is not None
        
        # HTTP Status Code (for login checks)
        if rule_type == "status_code":
            expected = validation_rule.get("expected")
            # Ensure we are comparing ints
            return int(result) == int(expected)
            
        # Body/String Contains (for specific flags)
        if rule_type == "body_contains":
            expected = validation_rule.get("expected")
            return expected in str(result)

    except Exception as e:
        print(f"[!] Validation Logic Error: {e}")
        return False
        
    return False