<?php

namespace cuteminded\Agent;

use BadMethodCallException;
use Detection\MobileDetect;
use Jaybizzle\CrawlerDetect\CrawlerDetect;

class Agent extends MobileDetect
{
    /**
     * Version type constants (matching parent class)
     */
    protected const VERSION_TYPE_STRING = 'text';
    protected const VERSION_TYPE_FLOAT = 'float';
    protected const VERSION_REGEX = '([\w._\+]+)';

    /**
     * List of desktop devices.
     * @var array
     */
    protected static array $desktopDevices = [
        'Macintosh' => 'Macintosh',
    ];

    /**
     * List of additional operating systems.
     * @var array
     */
    protected static array $additionalOperatingSystems = [
        'Windows' => 'Windows',
        'Windows NT' => 'Windows NT',
        'OS X' => 'Mac OS X',
        'Debian' => 'Debian',
        'Ubuntu' => 'Ubuntu',
        'Macintosh' => 'PPC',
        'OpenBSD' => 'OpenBSD',
        'Linux' => 'Linux',
        'ChromeOS' => 'CrOS',
    ];

    /**
     * List of additional browsers.
     * @var array
     */
    protected static array $additionalBrowsers = [
        'Opera Mini' => 'Opera Mini',
        'Opera' => 'Opera|OPR',
        'Edge' => 'Edge|Edg',
        'Coc Coc' => 'coc_coc_browser',
        'UCBrowser' => 'UCBrowser',
        'Vivaldi' => 'Vivaldi',
        'Chrome' => 'Chrome',
        'Firefox' => 'Firefox',
        'Safari' => 'Safari',
        'IE' => 'MSIE|IEMobile|MSIEMobile|Trident/[.0-9]+',
        'Netscape' => 'Netscape',
        'Mozilla' => 'Mozilla',
        'WeChat'  => 'MicroMessenger',
    ];

    /**
     * List of additional properties.
     * @var array
     */
    protected static array $additionalProperties = [
        // Operating systems
        'Windows' => 'Windows NT [VER]',
        'Windows NT' => 'Windows NT [VER]',
        'OS X' => 'OS X [VER]',
        'BlackBerryOS' => ['BlackBerry[\w]+/[VER]', 'BlackBerry.*Version/[VER]', 'Version/[VER]'],
        'AndroidOS' => 'Android [VER]',
        'ChromeOS' => 'CrOS x86_64 [VER]',

        // Browsers
        'Opera Mini' => 'Opera Mini/[VER]',
        'Opera' => [' OPR/[VER]', 'Opera Mini/[VER]', 'Version/[VER]', 'Opera [VER]'],
        'Netscape' => 'Netscape/[VER]',
        'Mozilla' => 'rv:[VER]',
        'IE' => ['IEMobile/[VER];', 'IEMobile [VER]', 'MSIE [VER];', 'rv:[VER]'],
        'Edge' => ['Edge/[VER]', 'Edg/[VER]'],
        'Vivaldi' => 'Vivaldi/[VER]',
        'Coc Coc' => 'coc_coc_browser/[VER]',
    ];

    /**
     * @var CrawlerDetect|null
     */
    protected static ?CrawlerDetect $crawlerDetect = null;

    /**
     * Get all detection rules. These rules include the additional
     * platforms and browsers.
     * @return array
     */
    public static function getDetectionRulesExtended(): array
    {
        static $rules;

        if (!$rules) {
            $rules = static::mergeRules(
                static::$desktopDevices,
                parent::getPhoneDevices(),
                parent::getTabletDevices(),
                parent::getOperatingSystems(),
                static::$additionalOperatingSystems,
                parent::getBrowsers(),
                static::$additionalBrowsers
            );
        }

        return $rules;
    }

    /**
     * Get detection rules
     * @return array
     */
    public function getRules(): array
    {
        return static::getDetectionRulesExtended();
    }

    /**
     * @return CrawlerDetect
     */
    public function getCrawlerDetect(): CrawlerDetect
    {
        if (static::$crawlerDetect === null) {
            static::$crawlerDetect = new CrawlerDetect();
        }

        return static::$crawlerDetect;
    }

    /**
     * Get all browsers including additional ones
     * @return array
     */
    public static function getAllBrowsers(): array
    {
        return static::mergeRules(
            static::$additionalBrowsers,
            parent::getBrowsers()
        );
    }

    /**
     * Get all operating systems including additional ones
     * @return array
     */
    public static function getAllOperatingSystems(): array
    {
        return static::mergeRules(
            parent::getOperatingSystems(),
            static::$additionalOperatingSystems
        );
    }

    /**
     * Get all platforms (alias for getAllOperatingSystems)
     * @return array
     */
    public static function getPlatforms(): array
    {
        return static::getAllOperatingSystems();
    }

    /**
     * Get desktop devices
     * @return array
     */
    public static function getDesktopDevices(): array
    {
        return static::$desktopDevices;
    }

    /**
     * Get all properties including additional ones
     * @return array
     */
    public static function getAllProperties(): array
    {
        return static::mergeRules(
            static::$additionalProperties,
            parent::getProperties()
        );
    }

    /**
     * Get accept languages.
     * @param string|null $acceptLanguage
     * @return array
     */
    public function languages(?string $acceptLanguage = null): array
    {
        if ($acceptLanguage === null) {
            $acceptLanguage = $this->getHttpHeader('HTTP_ACCEPT_LANGUAGE');
        }

        if (!$acceptLanguage) {
            return [];
        }

        $languages = [];

        // Parse accept language string.
        foreach (explode(',', $acceptLanguage) as $piece) {
            $parts = explode(';', $piece);
            $language = strtolower($parts[0]);
            $priority = empty($parts[1]) ? 1. : floatval(str_replace('q=', '', $parts[1]));

            $languages[$language] = $priority;
        }

        // Sort languages by priority.
        arsort($languages);

        return array_keys($languages);
    }

    /**
     * Match a detection rule and return the matched key.
     * @param  array $rules
     * @param  string|null $userAgent
     * @return string|false
     */
    protected function findDetectionRulesAgainstUA(array $rules, ?string $userAgent = null): string|false
    {
        $ua = $userAgent ?? $this->getUserAgent();

        // Loop given rules
        foreach ($rules as $key => $regex) {
            if (empty($regex)) {
                continue;
            }

            if (is_array($regex)) {
                $regex = implode('|', $regex);
            }

            // Check match (use # as delimiter to avoid conflicts with / in patterns)
            if (preg_match('#' . $regex . '#is', $ua)) {
                return $key;
            }
        }

        return false;
    }

    /**
     * Use only mobile-specific rules when evaluating generic mobile detection to avoid
     * desktop browsers/OS entries from the extended rule set triggering a match.
     */
    protected function matchUserAgentWithFirstFoundMatchingRule(): bool
    {
        $mobileRules = static::mergeRules(
            parent::getPhoneDevices(),
            parent::getTabletDevices(),
            parent::getOperatingSystems(),
            parent::getBrowsers()
        );

        return (bool) $this->findDetectionRulesAgainstUA($mobileRules);
    }

    /**
     * Get the browser name.
     * @param  string|null $userAgent
     * @return string|false
     */
    public function browser(?string $userAgent = null): string|false
    {
        return $this->findDetectionRulesAgainstUA(static::getAllBrowsers(), $userAgent);
    }

    /**
     * Get the platform name.
     * @param  string|null $userAgent
     * @return string|false
     */
    public function platform(?string $userAgent = null): string|false
    {
        return $this->findDetectionRulesAgainstUA(static::getPlatforms(), $userAgent);
    }

    /**
     * Get the device name.
     * @param  string|null $userAgent
     * @return string|false
     */
    public function device(?string $userAgent = null): string|false
    {
        $rules = static::mergeRules(
            static::getDesktopDevices(),
            parent::getPhoneDevices(),
            parent::getTabletDevices()
        );

        return $this->findDetectionRulesAgainstUA($rules, $userAgent);
    }

    /**
     * Check if the device is a desktop computer.
     * @return bool
     */
    public function isDesktop(): bool
    {
        // Check specifically for cloudfront headers if the useragent === 'Amazon CloudFront'
        if ($this->getUserAgent() === 'Amazon CloudFront') {
            $cfHeaders = $this->getHttpHeaders();
            if(array_key_exists('HTTP_CLOUDFRONT_IS_DESKTOP_VIEWER', $cfHeaders)) {
                return $cfHeaders['HTTP_CLOUDFRONT_IS_DESKTOP_VIEWER'] === 'true';
            }
        }

        return !$this->isMobile() && !$this->isTablet() && !$this->isRobot();
    }

    /**
     * Check if the device is a mobile phone.
     * @return bool
     */
    public function isPhone(): bool
    {
        return $this->isMobile() && !$this->isTablet();
    }

    /**
     * Get the robot name.
     * @param  string|null $userAgent
     * @return string|false
     */
    public function robot(?string $userAgent = null): string|false
    {
        $ua = $userAgent ?? $this->getUserAgent();
        if ($this->getCrawlerDetect()->isCrawler($ua)) {
            return ucfirst($this->getCrawlerDetect()->getMatches());
        }

        return false;
    }

    /**
     * Check if device is a robot.
     * @param  string|null $userAgent
     * @return bool
     */
    public function isRobot(?string $userAgent = null): bool
    {
        $ua = $userAgent ?? $this->getUserAgent();
        return $this->getCrawlerDetect()->isCrawler($ua);
    }

    /**
     * Get the device type
     * @return string
     */
    public function deviceType(): string
    {
        if ($this->isDesktop()) {
            return "desktop";
        } elseif ($this->isPhone()) {
            return "phone";
        } elseif ($this->isTablet()) {
            return "tablet";
        } elseif ($this->isRobot()) {
            return "robot";
        }

        return "other";
    }

    /**
     * Get version of a property
     * @param string $propertyName
     * @param string $type
     * @return string|float|false
     */
    public function version(string $propertyName, string $type = self::VERSION_TYPE_STRING): string|float|false
    {
        if (empty($propertyName)) {
            return false;
        }

        // set the $type to the default if we don't recognize the type
        if ($type !== self::VERSION_TYPE_STRING && $type !== self::VERSION_TYPE_FLOAT) {
            $type = self::VERSION_TYPE_STRING;
        }

        $properties = static::getAllProperties();

        // Check if the property exists in the properties array.
        if (true === isset($properties[$propertyName])) {

            // Prepare the pattern to be matched.
            // Make sure we always deal with an array (string is converted).
            $properties[$propertyName] = (array) $properties[$propertyName];

            foreach ($properties[$propertyName] as $propertyMatchString) {
                if (is_array($propertyMatchString)) {
                    $propertyMatchString = implode("|", $propertyMatchString);
                }

                $propertyPattern = str_replace('[VER]', static::VERSION_REGEX, $propertyMatchString);

                // Identify and extract the version.
                preg_match(sprintf('#%s#is', $propertyPattern), $this->getUserAgent() ?? '', $match);

                if (false === empty($match[1])) {
                    if ($type === self::VERSION_TYPE_FLOAT) {
                        return $this->prepareVersionNo($match[1]);
                    }
                    return $match[1];
                }
            }
        }

        return false;
    }

    /**
     * Prepare version number.
     *
     * @param string $ver
     * @return float
     */
    public function prepareVersionNo(string $ver): float
    {
        $ver = str_replace(['_', ' ', '/'], '.', $ver);
        $arrVersion = explode('.', $ver, 2);

        if (isset($arrVersion[1])) {
            $arrVersion[1] = (string)@str_replace('.', '', $arrVersion[1]);
        }

        return (float)implode('.', $arrVersion);
    }

    /**
     * Merge multiple rules into one array.
     * @param array ...$all
     * @return array
     */
    protected static function mergeRules(array ...$all): array
    {
        $merged = [];

        foreach ($all as $rules) {
            foreach ($rules as $key => $value) {
                if (empty($merged[$key])) {
                    $merged[$key] = $value;
                } elseif (is_array($merged[$key])) {
                    if (is_array($value)) {
                        $merged[$key] = array_merge($merged[$key], $value);
                    } else {
                        $merged[$key][] = $value;
                    }
                } else {
                    if (is_array($value)) {
                        $merged[$key] = array_merge([$merged[$key]], $value);
                    } else {
                        $merged[$key] .= '|' . $value;
                    }
                }
            }
        }

        return $merged;
    }

    /**
     * Magic method for is*() calls
     * @param string $name
     * @param array $arguments
     * @return bool
     */
    public function __call(string $name, array $arguments): bool
    {
        // Make sure the name starts with 'is', otherwise
        if (!str_starts_with($name, 'is')) {
            throw new BadMethodCallException("No such method exists: $name");
        }

        $key = substr($name, 2);

        return $this->is($key);
    }
}
