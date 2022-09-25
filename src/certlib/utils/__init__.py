from collections import OrderedDict
from typing import Any, Dict, Optional


def _ismapping(o: Any) -> bool:
    """Is the object a mapping/mutable mapping object

    :param o: object"""
    return isinstance(o, (dict, OrderedDict))


def _isiterable(o: Any) -> bool:
    """Is the object a mapping/mutable mapping object

    :param o: object"""
    return isinstance(o, (list, set, tuple))


def flatdict(d: Dict | OrderedDict, sep: str = ".", pk: str = "") -> Optional[Dict[Any, Any]]:
    """Flattens a dictionary, including nested dictionaries or lists of dictionaries.

    :param d: mapping or mutable mapping (aka dict)
    :param sep: seperator string to maintain key uniqueness
    :param pk: parent key to include in any resulting subkeys to maintain key uniqueness"""
    result = dict()

    for key, val in d.items():
        if val and _ismapping(val):
            new_pk = f"{pk}{key}{sep}"
            deeper = flatdict(val, sep=sep, pk=new_pk)
            result.update({_k2: _v2 for _k2, _v2 in deeper.items()})
        elif val and _isiterable(val):
            for index, sublist in enumerate(val, start=1):
                if sublist and _ismapping(sublist):
                    new_pk = f"{pk}{key}{sep}{str(index)}{sep}"
                    deeper = flatdict(sublist, sep=sep, pk=new_pk)
                    result.update({_k2: _v2 for _k2, _v2 in deeper.items()})
                else:
                    new_pk = f"{pk}{key}{sep}{str(index)}"
                    result[new_pk] = val
        else:
            new_pk = f"{pk}{key}"
            result[new_pk] = val

    if result:
        return result
