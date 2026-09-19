#!/usr/bin/awk -f

# 2026, Script by Philipp Frenzel

function map_crypt(a) {
    if (a=="rfc3686(ctr(aes))")  return "AES-CTR [RFC3686]"
    if (a=="cbc(aes)")           return "AES-CBC [RFC3602]"
    if (a=="cbc(des3_ede)")      return "TripleDES-CBC [RFC2451]"
    if (a=="cbc(des)")           return "DES-CBC [RFC2405]"
    if (a=="ecb(cipher_null)" || a=="") return "NULL"
    return ""
}
function map_aead(a) {
    if (a=="rfc4106(gcm(aes))")  return "AES-GCM [RFC4106]"
    if (a=="rfc4309(ccm(aes))")  return "AES-CCM [RFC4309]"
    return ""
}
function map_auth(a) {
    if (a=="hmac(sha1)")    return "HMAC-SHA-1-96 [RFC2404]"
    if (a=="hmac(md5)")     return "HMAC-MD5-96 [RFC2403]"
    if (a=="hmac(sha256)")  return "HMAC-SHA-256-128 [RFC4868]"
    if (a=="hmac(sha384)")  return "HMAC-SHA-384-192 [RFC4868]"
    if (a=="hmac(sha512)")  return "HMAC-SHA-512-256 [RFC4868]"
    if (a=="xcbc(aes)")     return "AES-XCBC-MAC-96 [RFC3566]"
    if (a=="digest_null" || a=="") return "NULL"
    return ""
}
function emit(   algo, akey_out, aalgo_out) {
    if (!in_sa || spi=="") { reset(); return }
    if (event=="Deleted" || event=="Expired") { reset(); return }
    if (aead!="") {
        algo = map_aead(aead)
        aalgo_out = "NULL"; akey_out = ""
    } else {
        algo = map_crypt(ealgo)
        aalgo_out = map_auth(aalgo)
        akey_out  = akey
    }
    if (algo=="") {
        print "# skip " src " -> " dst " spi=" spi " (" ealgo aead ")" > "/dev/stderr"
        fflush("/dev/stderr"); reset(); return
    }
    printf "\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\"\n", \
        family, src, dst, spi, algo, ekey, aalgo_out, akey_out
    fflush()
    reset()
}
function reset() {
    in_sa=0; event=""
    src=dst=spi=ealgo=ekey=aalgo=akey=aead=family=""
}

# Event header from `ip xfrm monitor`: "Added ", "Updated ", "Deleted ", "Expired "
/^(Added|Updated|Deleted|Expired) / {
    emit()              # flush any prior block
    event=$1
    # Same line continues with "src X dst Y" — fall through to src handler
}

# Start of an SA block (either after an event header or from `ip xfrm state`)
/(^| )src [^ ]+ dst [^ ]+/ {
    if (in_sa) emit()
    in_sa=1
    if (event=="") event="State"
    for (i=1;i<=NF;i++) {
        if ($i=="src") { src=$(i+1); sub(/\/.*/,"",src); sub(/\r/,"",src) }
        if ($i=="dst") { dst=$(i+1); sub(/\/.*/,"",dst); sub(/\r/,"",dst) }
    }
    family = (src ~ /:/) ? "IPv6" : "IPv4"
    next
}

/proto esp/         { for (i=1;i<=NF;i++) if ($i=="spi") spi=$(i+1) }
/^[ \t]*enc /       { ealgo=$2; ekey=$3; sub(/\r/,"",ekey) }
/^[ \t]*auth-trunc/ { aalgo=$2; akey=$3; sub(/\r/,"",akey) }
/^[ \t]*auth /      { if (aalgo=="") { aalgo=$2; akey=$3 } }
/^[ \t]*aead /      { aead=$2;  ekey=$3 }

# Blank line = end of block in monitor output → emit immediately
/^[[:space:]]*$/    { emit() }

END { emit() }
