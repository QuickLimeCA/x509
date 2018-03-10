pub mod x509 {
    extern crate simple_asn1;
    extern crate num;

    use self::simple_asn1::{ToASN1, FromASN1, ASN1Block, ASN1Class, ASN1DecodeErr, ASN1EncodeErr};
    use self::num::bigint::BigInt;

    #[derive(Debug, PartialEq)]
    pub enum Version {
        V1,
        V2,
        V3   
    }

    impl ToASN1 for Version {
        type Error = ASN1EncodeErr;

        fn to_asn1_class(&self, _c: ASN1Class) -> Result<Vec<ASN1Block>, Self::Error> {
            let val = match self {
                &Version::V1 => 0,
                &Version::V2 => 1,
                &Version::V3 => 2,
            };
            Result::Ok(vec![ASN1Block::Integer(ASN1Class::Universal, 0, BigInt::from(val))])
        }
    }

    impl FromASN1 for Version {
        type Error = ASN1DecodeErr;

        fn from_asn1(v: &[ASN1Block]) -> Result<(Self, &[ASN1Block]), Self::Error> {
            let (head, tail) = v.split_at(1);
            match head[0] {
                ASN1Block::Integer(class, _, ref val) => {
                    match class {
                        ASN1Class::Universal => {
                            if val < &BigInt::from(0) || val > &BigInt::from(2) {
                                return Err(ASN1DecodeErr::UTF8DecodeFailure);
                            }
                            else if val == &BigInt::from(0) {
                                return Ok((Version::V1, &tail));
                            }
                            else if val == &BigInt::from(1) {
                                return Ok((Version::V2, &tail));
                            }
                            Ok((Version::V3, &tail))
                        },
                        _ => Err(ASN1DecodeErr::UTF8DecodeFailure)
                    }
                },
                _ => Err(ASN1DecodeErr::UTF8DecodeFailure)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate simple_asn1;

    use self::simple_asn1::{der_decode, der_encode, ASN1DecodeErr};

    use super::x509::Version;

    #[test]
    fn version_encodes_v1_correctly() {
        let expected = vec![0x02, 0x01, 0x00];
        let actual = der_encode(&Version::V1).unwrap();
        assert_eq!(expected, actual);
    }

    #[test]
    fn version_encodes_v2_correctly() {
        let expected = vec![0x02, 0x01, 0x01];
        let actual = der_encode(&Version::V2).unwrap();
        assert_eq!(expected, actual);
    }

    #[test]
    fn version_encodes_v3_correctly() {
        let expected = vec![0x02, 0x01, 0x02];
        let actual = der_encode(&Version::V3).unwrap();
        assert_eq!(expected, actual);
    }

    #[test]
    fn version_decodes_v1_correctly() {
        let expected = Version::V1;
        let actual = der_decode::<Version>(&vec![0x02, 0x01, 0x00]).unwrap();
        assert_eq!(expected, actual);
    }

    #[test]
    fn version_decodes_v2_correctly() {
        let expected = Version::V2;
        let actual = der_decode::<Version>(&vec![0x02, 0x01, 0x01]).unwrap();
        assert_eq!(expected, actual);
    }

    #[test]
    fn version_decodes_v3_correctly() {
        let expected = Version::V3;
        let actual = der_decode::<Version>(&vec![0x02, 0x01, 0x02]).unwrap();
        assert_eq!(expected, actual);
    }

    #[test]
    fn version_should_err_when_unsupported_version_supplied() {
        let error = der_decode::<Version>(&vec![0x02, 0x01, 0x03]).unwrap_err();
        assert_eq!(error, ASN1DecodeErr::UTF8DecodeFailure)
    }
}