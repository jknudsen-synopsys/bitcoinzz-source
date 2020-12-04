package com.example.sdk;

import java.security.*;
import java.util.Arrays;

import com.synopsys.defensics.api.message.*;
import com.synopsys.defensics.api.message.rule.CustomChecksum;

public class SHA256x2 implements CustomChecksum {
  @Override
  public byte[] calculate(SDKEngine engine, byte[] data) {
    MessageDigest mDigest;
    try {
      mDigest = MessageDigest.getInstance("SHA-256");
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException(e);
    }
    byte[] shaTheFirst = mDigest.digest(data);
    byte[] shaTheSecond = mDigest.digest(shaTheFirst);
    return Arrays.copyOfRange(shaTheSecond, 0, 4);
  }
}
