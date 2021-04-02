import importlib

filter_cache = {}


def load_filters(cfg, filter_type):
    filter_chain = []

    for f in cfg[filter_type]:
        module = importlib.import_module(f['module'])
        clazz = module.__getattribute__(f['class'])

        try:
            filter_chain.append(filter_cache[clazz])
        except KeyError as e:
            instance = clazz(cfg)
            filter_cache[clazz] = instance
            filter_chain.append(instance)
    return filter_chain
