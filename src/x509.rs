pub mod x509 {
    extern crate simple_asn1;
    extern crate num;

    use self::simple_asn1::{ToASN1, ASN1Block, ASN1Class, ASN1EncodeErr};
    use self::num::bigint::BigInt;

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
}

#[cfg(test)]
mod tests {
    extern crate simple_asn1;

    use self::simple_asn1::der_encode;

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
}