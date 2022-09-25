#!/usr/local/bin/python3
from certlib.utils.certificates import get_certificates


if __name__ == "__main__":
    display_attrs = ["common_name",
                     "sha256",
                     "not_before_local_str",
                     "not_after_local_str"]
    fieldnames_str = ",".join(display_attrs)
    certificates = sorted(get_certificates(), key=lambda c: c.common_name)

    if certificates:
        print(fieldnames_str)

        for certificate in certificates:
            row = ",".join([getattr(certificate, attr, "''") or "''" for attr in display_attrs])
            print(row)
