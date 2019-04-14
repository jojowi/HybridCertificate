package org.bouncycastle.utils;

import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;

public class ByteArrayUtils {

    public static void replaceZeros(byte[] base, byte[] replace) {
        List<Byte> baseList = new LinkedList<>();
        for (byte b : base) {
            baseList.add(b);
        }
        List<Byte> sigList = new LinkedList<>();
        for (byte b : replace) {
            sigList.add(b);
        }
        int index = Collections.indexOfSubList(baseList, sigList);
        Arrays.fill(base, index, index + replace.length, (byte) 0);
    }
}
