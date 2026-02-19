package com.sentinelapi.scanner;

import com.sentinelapi.dto.Vulnerability;

import java.util.List;

public interface SecurityScanner {

    String getName();

    List<Vulnerability> scan(String targetUrl);
}

