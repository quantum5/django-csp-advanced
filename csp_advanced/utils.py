def callable_csp_dict(data):
    if callable(data):
        return data()
    result = {}
    for key, value in data.iteritems():
        if callable(value):
            result[key] = value()
        else:
            result[key] = value
    return result


def merge_csp_dict(template, override):
    result = template.copy()
    for key, value in override.iteritems():
        if key not in result:
            result[key] = value
            continue
        orig = result[key]
        if isinstance(orig, list):
            if orig == template[key]:
                result[key] = orig + list(value)
            else:
                orig += value
        elif isinstance(orig, set):
            if orig == template[key]:
                result[key] = orig.union(value)
            else:
                orig.update(value)
        elif isinstance(orig, tuple):
            result[key] = orig + tuple(value)
        else:
            result[key] = value
    return result
