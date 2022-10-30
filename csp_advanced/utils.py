def is_callable_csp_dict(data):
    if callable(data):
        return True
    if not isinstance(data, dict):
        return False
    return any(callable(value) for value in data.values())


def call_csp_dict(data, request, response):
    if callable(data):
        return data(request, response)

    result = {}
    for key, value in data.items():
        if callable(value):
            result[key] = value(request, response)
        else:
            result[key] = value
    return result


def merge_csp_dict(template, override):
    result = template.copy()
    for key, value in override.items():
        if key not in result:
            result[key] = value
            continue
        orig = result[key]
        if isinstance(orig, list):
            result[key] = orig + list(value)
        elif isinstance(orig, set):
            result[key] = orig.union(value)
        elif isinstance(orig, tuple):
            result[key] = orig + tuple(value)
        else:
            result[key] = value
    return result
