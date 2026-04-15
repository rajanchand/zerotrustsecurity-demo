// office hours: 9am to 4pm
// anything outside that counts as off hours
var OFFICE_HOURS = {
    START: 9,
    END: 16
};

// check if the given time is outside office hours
// takes timezone offset in minutes (from browser getTimezoneOffset)
function isOffHours(date, timezoneOffsetMinutes) {
    var d = date || new Date();
    var offsetHours = Math.round((timezoneOffsetMinutes || 0) / 60);
    var hour = d.getHours() + offsetHours;
    hour = (hour + 24) % 24;

    // off hours = before 9am or after 4pm (16:00)
    if (hour >= OFFICE_HOURS.END || hour < OFFICE_HOURS.START) {
        return true;
    }
    return false;
}

module.exports = {
    SECURITY_POLICY: OFFICE_HOURS,
    isOffHours: isOffHours
};
