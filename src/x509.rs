pub mod x509 {
    extern crate simple_asn1;
    extern crate num;

    use self::simple_asn1::{ToASN1, FromASN1, ASN1Block, ASN1Class, ASN1DecodeErr, ASN1EncodeErr};
    use self::num::bigint::BigInt;
    use self::num::ToPrimitive;

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

    #[derive(Debug, PartialEq)]
    pub struct CertificateSerialNumber(pub i64);

    impl ToASN1 for CertificateSerialNumber {
        type Error = ASN1EncodeErr;

        fn to_asn1_class(&self, _c: ASN1Class) -> Result<Vec<ASN1Block>, Self::Error> {
            Result::Ok(vec![ASN1Block::Integer(ASN1Class::Universal, 0, BigInt::from(self.0))])
        }
    }

    impl FromASN1 for CertificateSerialNumber {
        type Error = ASN1DecodeErr;

        fn from_asn1(v: &[ASN1Block]) -> Result<(Self, &[ASN1Block]), Self::Error> {
            let (head, tail) = v.split_at(1);
            match head[0] {
                ASN1Block::Integer(class, _, ref val) => {
                    match class {
                        ASN1Class::Universal => Ok((CertificateSerialNumber(BigInt::to_i64(val).unwrap()), &tail)),
                        _ => Err(ASN1DecodeErr::UTF8DecodeFailure)
                    }
                },
                _ => Err(ASN1DecodeErr::UTF8DecodeFailure)
            }
        }
    }
}

#[cfg(test)]
mod version_tests {
    extern crate simple_asn1;

    use self::simple_asn1::{der_decode, der_encode, from_der, FromASN1, ASN1Block, ASN1DecodeErr};

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

    #[test]
    fn version_should_not_break_decoding_subsequent_blocks() {
        // ASN.1 Sequence of 3 Versions: v1, v2 & v3
        let test_data = vec![0x30, 0x09, 0x02, 0x01, 0x00, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02];
        let expected = vec![Version::V1, Version::V2, Version::V3];
        let seq = &from_der(&test_data).unwrap()[0];
        match seq {
            &ASN1Block::Sequence(_, _, ref blocks) => {
                let (first_actual, first_tail) = Version::from_asn1(&blocks).unwrap();
                let (second_actual, second_tail) = Version::from_asn1(&first_tail).unwrap();
                let (third_actual, _) = Version::from_asn1(&second_tail).unwrap();
                assert_eq!(expected[0], first_actual);
                assert_eq!(expected[1], second_actual);
                assert_eq!(expected[2], third_actual);
            },
            _ => panic!("Not a sequence")
        }
    }
}

#[cfg(test)]
mod certificate_serial_numbers_tests {
    extern crate simple_asn1;

    use self::simple_asn1::{der_decode, der_encode, from_der, FromASN1, ASN1Block, ASN1DecodeErr};

    use super::x509::CertificateSerialNumber;

    macro_rules! decoding_test {
        ($name:ident, $input:expr, $expected:expr) => {
            #[test]
            fn $name() {
                let actual = der_decode::<CertificateSerialNumber>($input).unwrap();
                let expected = CertificateSerialNumber($expected);
                assert_eq!(expected, actual);
            }
        }
    }

    macro_rules! encoding_test {
        ($name:ident, $input:expr, $expected:expr) => {
            #[test]
            fn $name() {
                let actual = der_encode(&CertificateSerialNumber($input)).unwrap();
                let expected = $expected;
                assert_eq!(expected, actual);
            }
        }
    }

    decoding_test!(certificate_serial_number_should_decode_0, &vec![0x02, 0x01, 0x00], 0);
    decoding_test!(certificate_serial_number_should_decode_1, &vec![0x02, 0x01, 0x01], 1);
    decoding_test!(certificate_serial_number_should_decode_negative_1, &vec![0x02, 0x01, 0xFF], -1);
    decoding_test!(certificate_serial_number_should_decode_negative_42, &vec![0x02, 0x01, 0xD6], -42);
    decoding_test!(certificate_serial_number_should_decode_42, &vec![0x02, 0x01, 0x2A], 42);
    decoding_test!(certificate_serial_number_should_decode_i64_max, &vec![0x02, 0x08, 0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF], 9223372036854775807);
    decoding_test!(certificate_serial_number_should_decode_i64_min, &vec![0x02, 0x08, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], -9223372036854775808);

    encoding_test!(certificate_serial_number_should_encode_0, 0, vec![0x02, 0x01, 0x00]);
    encoding_test!(certificate_serial_number_should_encode_1, 1, vec![0x02, 0x01, 0x01]);
    encoding_test!(certificate_serial_number_should_encode_negative_1, -1, vec![0x02, 0x01, 0xFF]);
    encoding_test!(certificate_serial_number_should_encode_negative_42, -42, vec![0x02, 0x01, 0xD6]);
    encoding_test!(certificate_serial_number_should_encode_42, 42, vec![0x02, 0x01, 0x2A]);
    encoding_test!(certificate_serial_number_should_encode_i64_max, 9223372036854775807, vec![0x02, 0x08, 0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
    encoding_test!(certificate_serial_number_should_encode_i64_min, -9223372036854775808, vec![0x02, 0x08, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
}