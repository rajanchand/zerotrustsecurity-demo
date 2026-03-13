/**
 * Off-hours settings.
 * Before 9am and after 6pm is considered off-hours.
 */
var OFF_HOURS = {
    START: 18, // 6pm - start of off-hours
    END: 9     // 9am - end of off-hours
};

/**
 * Check if the given time is outside working hours.
 * Returns true if it's before 9am or after 6pm.
 */
function isOffHours(date, hourOffset) {
    var d = date || new Date();
    var hour = d.getHours() + (hourOffset || 0);
    hour = (hour + 24) % 24; // handle negative offsets

    if (hour >= OFF_HOURS.START || hour < OFF_HOURS.END) {
        return true;
    }
    return false;
}

module.exports = {
    SECURITY_POLICY: OFF_HOURS,
    isOffHours: isOffHours
};
