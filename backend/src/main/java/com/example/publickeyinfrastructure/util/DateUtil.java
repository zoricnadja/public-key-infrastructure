package com.example.publickeyinfrastructure.util;

import com.example.publickeyinfrastructure.config.Constants;
import com.example.publickeyinfrastructure.model.CertificateType;

import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;

public class DateUtil {
    public static Date generateStartTime() {
        LocalDateTime startOfDay = LocalDateTime.now().toLocalDate().atStartOfDay();
        return localDateTimeToDate(startOfDay);
    }

    public static Date generateEndTime(Date date, CertificateType certificateType) {
        LocalDateTime localDateTime = dateToLocalDateTime(date);
        LocalDateTime endTime;
        if(certificateType.equals(CertificateType.ROOT))
            endTime = localDateTime.plusYears(Constants.ROOT_CERTIFICATE_DURATION);
        else if(certificateType.equals(CertificateType.INTERMEDIATE))
            endTime = localDateTime.plusYears(Constants.INTERMEDIATE_CERTIFICATE_DURATION);
        else
            endTime = localDateTime.plusYears(Constants.CERTIFICATE_DURATION);
        return localDateTimeToDate(endTime);
    }

    private static LocalDateTime dateToLocalDateTime(Date date) {
        return LocalDateTime.ofInstant(date.toInstant(), ZoneId.systemDefault());
    }

    private static Date localDateTimeToDate(LocalDateTime localDateTime) {
        return Date.from(localDateTime.atZone(ZoneId.systemDefault()).toInstant());
    }
}
