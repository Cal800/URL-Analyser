
import java.util.Scanner;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

import java.time.LocalDate;
import java.time.temporal.ChronoUnit;

public class Main {

    private static final String DB_HOST = System.getenv("DB_HOST") != null ? System.getenv("DB_HOST") : "localhost";
    private static final String DB_URL = "jdbc:postgresql://" + DB_HOST + ":5432/postgres";
    private static final String DB_USER = System.getenv("DB_USER") != null ? System.getenv("DB_USER") : "postgres";
    private static final String DB_PASS = System.getenv("DB_PASS");


    public static void main(String[] args) {

        Scanner UI = new Scanner(System.in);
        boolean T = true;
        int sessionUrls = 0;

        if (DB_PASS == null) {
            System.out.println("DB_PASS environment variable is not set.");
            return;
        }

        while (T) {

            System.out.println("URL Security Checker");
            System.out.println("By CF Security");
            System.out.println("Type '1' for Risk Score Breakdown");


            boolean validURL = false;
            String url = "";
            int DangerR = 0;
            boolean Scorrect = true;
            boolean riskS = false;
            String TestCFailed = "";
            boolean again = false;
            String againS = "";

            boolean URLSh = true;
            boolean URLIF = true;

            boolean againL = false;


            while (!validURL) {

                System.out.print("\nEnter the URL >>> ");
                url = UI.nextLine().trim();

                if (url.length() >= 10) {
                    validURL = true;
                } else if (url.equalsIgnoreCase("1")) {
                    System.out.println("\n\t\t    RISK SCORE BREAKDOWN");
                    System.out.println("\t\t   -----------------------");
                    System.out.println("1) Test Case 2 - NO HTTPS structure - +2");
                    System.out.println("2) Test Case 3 - NON valid Regex characters - +4");
                    System.out.println("3) Test Case 4 - NOT in the valid ASCII range - +5");
                    System.out.println("4) Test Case 5 - Exceeds a safe number of dots - +2");
                    System.out.println("5) Test Case 6 - Detected a raw IP Address - +9");
                    System.out.println("6) Test Case 7 - Detected suspicious keywords - +3");
                    System.out.println("7) Test Case 8 - Flagged an untrusted TLD extension - +4");
                    System.out.println("8) Test Case 9 - Recognised a recently added domain - +4");

                    System.out.println("\nThe overall danger rating does NOT guarantee safety ");
                    System.out.println("but utilises recognisable cybersecurity practices ");
                    System.out.println("regarding malicious web url factors researched from");
                    System.out.println("Cyber Threat Intelligence & Incident Response\n");
                    System.out.println("\t\t  ===Use at your OWN risk===");

                } else {
                    System.out.println("Please enter a Valid URL length!");
                }

            } //url while

            System.out.println("====================\n");
            long startTime = System.nanoTime();
            System.out.println("Analysing URL.....\n");

            System.out.println(url);

            System.out.println("\nPreTests\n");

            int urlShortener = isUrlShortened(url);

            if (urlShortener == 1) {
                System.out.println("Your URL uses 'bit.ly' a popular url shortener\nused by attackers to hide malicious activity");
                System.out.println("This tool was NOT built to analyse \nthese types of URLs and as a result:");
                System.out.println("Pre Test 1 - Result: CRITICAL FAIL");
                System.out.println("Use a url expander -> before this program");
                URLSh = false;
            } else if (urlShortener == 2) {
                System.out.println("Your URL uses 'TinyURL' a popular url shortener\nused by attackers to hide malicious activity");
                System.out.println("This tool was NOT built to analyse \nthese types of URLs and as a result:");
                System.out.println("Pre Test 1 - Result: CRITICAL FAIL");
                System.out.println("Use a url expander -> before this program");
                URLSh = false;
            } else if (urlShortener == 3) {
                System.out.println("Your URL uses 'rebrand' a popular url shortener\nused by attackers to hide malicious activity");
                System.out.println("This tool was NOT built to analyse \nthese types of URLs and as a result:");
                System.out.println("Pre Test 1 - Result: CRITICAL FAIL");
                System.out.println("Use a url expander -> before this program");
                URLSh = false;
            } else if (urlShortener == 0) {
                System.out.println("Your URL avoids the use of URL compressor/shortener");
                System.out.println("Pre Test 1 - Result: PASS");
                URLSh = true;


            }

            boolean isFlagged = checkDatabase(url);

            if (isFlagged == true) {
                System.out.println("\nYour URL was detected inside the database");
                System.out.println("With a Danger Rating of -> " + getDangerRating(url));
                System.out.println("This URL has been knowingly involved with malicious activity");
                System.out.println("Using/Accessing this URL is a MAJOR security risk");
                System.out.println("URL -> [BLOCKED]");
                System.out.println("AVOID AT ALL COSTS");
                System.out.println("Pre Test 2 - Result: CRITICAL FAILURE");
                URLIF = false;

            } else {
                System.out.println("Your URL has NOT been detected in our malicious activity database");
                System.out.println("Pre Test 2 - Result: PASS");
            }

            boolean urlHashed = isTrustedUrl(url);
            boolean URLhS = true;

            if (urlHashed == true && isHTTPS(url) == true) {
                System.out.println("\nYour website belongs in the list of the most secure \nURLS in the world (according to Cloudflare)");
                System.out.println("it is COMPLETELY safe to use this url link! \n(browse/use at own risk)");
                System.out.println("here is the link -> " + url);
                System.out.println("Pre Test 3 - Result: PASS");
                URLhS = false;

            } else {
                System.out.println("\nYour URL does not appear on the approved list");
                System.out.println("Testing will commence....");
                URLhS = true;
            }


            if (URLSh == true) {

                if (URLIF == true) {

                    if (URLhS == true) {

                        boolean urlS = isValidS(url);

                        System.out.println("\n-> Test 1:");


                        if (urlS == true) {
                            System.out.println("This URL has a valid structure");
                            System.out.println("Result: PASS");
                        } else {
                            System.out.println("This URL does not have the correct structure - cannot continue");
                            System.out.println("Result: CRITICAL FAIL");
                            Scorrect = false;
                        }

                        if (Scorrect == true) {


                            boolean urlH = isHTTPS(url);

                            System.out.println("\n-> Test 2:");

                            if (urlH == true) {
                                System.out.println("Your URL contains https which indicates the use of encryption");
                                System.out.println("Result: PASS");

                            } else {
                                System.out.println("Your URL does NOT use encryption");
                                System.out.println("Result: FAIL");
                                TestCFailed += "\n-> Test Case 2 (+2)";

                                DangerR += 2;
                            }


                            boolean urlC = noHiddenChars(url);
                            System.out.println("\n-> Test 3:");

                            if (urlC == true) {
                                System.out.println("Your URL uses valid characters");
                                System.out.println("Result: PASS");
                            } else {
                                System.out.println("Your URL may contain unknown characters");
                                System.out.println("Result: FAIL");
                                TestCFailed += "\n-> Test Case 3 (+4)";
                                DangerR += 4;
                            }

                            boolean urlA = ASCIIcheck(url);
                            System.out.println("\n-> Test 4:");


                            if (urlA == true) {
                                System.out.println("Your URL contains all valid ASCII characters");
                                System.out.println("Result: PASS");
                            } else {
                                System.out.println("Your URL contains values outside of valid ASCII");
                                System.out.println("Result: FAIL");
                                TestCFailed += "\n-> Test Case 4 (+5)";
                                DangerR += 5;
                            }


                            boolean urlD = countDots(url);
                            System.out.println("\n-> Test 5:");

                            if (urlD == true) {
                                System.out.println("Your URL has a safe number of .'s'");
                                System.out.println("Result: PASS");
                            } else {
                                System.out.println("Your URL contains a suspicious number of .'s'");
                                System.out.println("Result: FAIL");
                                TestCFailed += "\n-> Test Case 5 (+2)";
                                DangerR += 2;
                            }

                            boolean urlIP = checkforIP(url);
                            System.out.println("\n-> Test 6:");

                            if (urlIP == true) {
                                System.out.println("Your URL is not only an IP");
                                System.out.println("Result: PASS");
                            } else {
                                System.out.println("Your url contains a plain IP address");
                                System.out.println("Result: FAIL");
                                TestCFailed += "\n-> Test Case 6 (+9)";
                                DangerR += 9;
                            }

                            if (urlIP == true) {

                                System.out.println("\n-> Test 7:");

                                String[] urlK = checkforKeywords(url);
                                boolean empty = true;

                                for (int i = 0; i < urlK.length; i++) {
                                    String c = urlK[i];

                                    if (urlK[i] != null) {
                                        empty = false;
                                    }
                                }

                                if (empty == true) {
                                    System.out.println("Your URL does not contain any suspicious keywords");
                                    System.out.println("Result: PASS");
                                } else {
                                    System.out.println("Your URL contains keywords that are often linked with suspicious activity");
                                    System.out.println("Keywords detected:");
                                    DangerR += 3;

                                    for (int i = 0; i < urlK.length; i++) {
                                        if (urlK[i] != null) {
                                            System.out.println("-> " + urlK[i]);
                                        }
                                    }

                                    System.out.println("Result: FAIL");
                                    TestCFailed += "\n-> Test Case 7 (+3)";
                                }

                                System.out.println("\n-> Test 8:");

                                String urlT[] = checkTLD(url);
                                boolean empty1 = true;

                                for (int i = 0; i < urlT.length; i++) {
                                    String c = urlT[i];

                                    if (urlT[i] != null) {
                                        empty1 = false;
                                    }
                                }

                                if (empty1 == true) {
                                    System.out.println("Your TLD is not often associated with suspicious activity ");
                                    System.out.println("Result: PASS");
                                } else {
                                    System.out.println("Your TLD is often associated with suspicious activity");
                                    System.out.println("Suspicious TLD: ");
                                    DangerR += 4;


                                    for (int i = 0; i < urlT.length; i++) {
                                        if (urlT[i] != null) {
                                            System.out.println("-> " + urlT[i]);
                                        }
                                    }

                                    System.out.println("Result: FAIL");
                                    TestCFailed += "\n-> Test Case 8 (+4)";
                                }

                                boolean UrlTF = checkDomainAge(url);
                                System.out.println("\n-> Test Case 9");

                                if (UrlTF == false) {
                                    System.out.println("Your URL was inserted into the database MORE than 30 days ago");
                                    System.out.println("Result: PASS");
                                } else if (UrlTF == true) {
                                    System.out.println("Your URL was inserted into the database LESS than 30 days ago");
                                    System.out.println("This is commonly associated with malicious sites");
                                    System.out.println("Current Age of Domain ->" + getDomainAge(url));
                                    System.out.println("Result: FAIL");
                                    DangerR += 4;

                                    TestCFailed += "\n-> Test Case 9 (+4)";
                                }

                            } else {
                                System.out.println("\n==Test's 7,8,9 skipped - IP address detected==\n");
                            }

                            System.out.println("\n\n⚠️ Risk Calculator ⚠️ ");
                            System.out.println("\nCalculating Risk......\n");

                            if (TestCFailed.isEmpty()) {
                                System.out.println("All Cases Passed");
                                System.out.println("Your URL has been deemed safe");
                                System.out.println("URL link -> " + url);
                                System.out.println("Please use/browse at your own risk \nand stay aware while online");
                                System.out.println("Thank you for using this system");
                                System.out.println("\nCF Security 2026");
                                again = true;
                            } else {
                                System.out.println("Test Cases Failed:");
                                System.out.println(TestCFailed);
                                System.out.println("\nCalculating Overall Risk Score.....");
                                riskS = true;
                            }


                            if (riskS == true) {

                                System.out.println("Overall Danger Rating: " + DangerR);

                                System.out.println("\nActions Recommended\n");


if (DangerR == 0 || DangerR <= 3) {
  System.out.println("This URL is deemed safe however as with everything " +
  "\ntechnology based, use/browse with caution");
  System.out.println("URL link -> " + url);
  again = true;
} else if (DangerR >= 4 && DangerR <= 7) {
    System.out.println("This URL has been flagged as mildly suspicious due " +
    "\nto failing some test cases. As a result you " +
    "should proceed with \nextreme caution and take steps to protect yourself");
    System.out.println("URL link -> " + url);
    again = true;
} else if (DangerR >= 8) {
   System.out.println("This URL has been flagged as extremely suspicious with a " +
   "\nHIGH likelihood of being utilized for malicious activities \nAVOID at ALL costs");
   System.out.println("Url link -> [BLOCKED]");
   urlDBInsertion(url, DangerR);
  again = true;

 }
    }


                            //System.out.println("\nDanger Rating: " + DangerR);

                        } //Scorrect if


                        else if (Scorrect == false) {
                            System.out.println("\nURL Structure is NOT visible\n");
                            System.out.println("Tests 2 - 9 skipped");
                            System.out.println("\nPlease enter a valid url that follows the structure");
                            again = true;

                        }

                    } //URLhS if

                    else if (URLSh == true) {
                        System.out.println("\n\nPre-Tests PASSED");
                        System.out.println("Further Testing NOT required");
                        again = true;
                    }

                } //urlIF if

                else if (URLIF == false) {
                    again = true;
                }

            } //URLSh if

            else if (URLSh == false) {
                System.out.println("\nURL Shortener Detected\n");
                System.out.println("Please utilize a URL expansion tool");
                again = true;
            }

            long endTime = System.nanoTime();
            double elapsedMs = (endTime - startTime) / 1_000_000.0;
            System.out.printf("%nAnalysis completed in %.2f ms%n", elapsedMs);

            if (again == true) {

                sessionUrls++;

                while(againL == false) {
                    System.out.println("\nTo try another URL type '1' or press 'Q' to end the session");
                    System.out.print(">>> ");
                    againS = UI.nextLine().trim();

                    if (againS.equalsIgnoreCase("1")) {
                        validURL = false;
                        againL = true;
                    } else if (againS.equalsIgnoreCase("q")) {
                        System.out.println("\nThank you for using this system");
                        System.out.println("CF Security - 2026");
                        System.out.println("\nURLs analysed in this session -> " + sessionUrls);
                        againL = true;
                        T = false;
                    } else {
                        System.out.println("==Please enter a valid command==");
                    }
                }

            } //again if

        } //while true

        if (T == false) {
            UI.close();
        }

    } //main

    public static boolean isValidS(String url) {

        String u = url.toLowerCase();
        return u.startsWith("http://") || u.startsWith("https://");
    }

    public static boolean isHTTPS(String url) {

        return url.toLowerCase().startsWith("https://");
    }

    public static boolean noHiddenChars(String url) {
        if (url.matches("^[a-zA-Z0-9:/,\\.=\\?\\-_~&\\+%#]*$")) {
            return true;
        } else {
            return false;
        }
    }

    public static boolean ASCIIcheck(String url) {

        int AN = url.length();

        for (int i = 0; i < url.length(); i++) {

            char c = url.charAt(i);

            if ((c >= 65 && c <= 90) || (c >= 97 && c <= 122)) {
                AN--;
            } else if (c == 58 || c == 47 || c == 44 || c == 46 || c == 61 || c == 63) {
                AN--;
            } else if (c >= 48 && c <= 57) {
                AN--;
            } else if (c == 45 || c == 95 || c == 126 || c == 38 || c == 43 || c == 37 || c == 35) {
                AN--;
            }
        }

        if (AN == 0) {
            return true;
        } else {
            return false;
        }
    }

    public static boolean countDots(String url) {
        int totalDotCount = 0;

        for (int i = 0; i < url.length(); i++) {
            char c = url.charAt(i);

            if (c == '.') {
                totalDotCount++;
            }
        }

        if (totalDotCount <= 3) {
            return true;
        } else {
            return false;
        }
    }

    public static boolean checkforIP(String url) {

        if (url.matches(".*\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}.*")) {
            return false;
        } else {
            return true;
        }

    }

    public static String[] checkforKeywords(String url) {

        String lowerCase = url.toLowerCase();

        String[] keywords = {"secure", "gift", "free", "bank", "verify", "scam", "competition"};
        String[] keywordsF = new String[keywords.length];
        int keywordsFound = 0;

        for (int i = 0; i < keywords.length; i++) {
            String c = keywords[i];

            if (lowerCase.contains(c)) {
                keywordsF[i] = c;
            }
        }

        return keywordsF;

    }

    public static String[] checkTLD(String url) {

        String url1 = url.toLowerCase().replaceAll("^https?://", "").replaceAll("[/?#:].*", "");

        String[] keywords = {".biz", ".zip", ".mov", ".cn", ".xyz"};
        String[] keywordsF = new String[keywords.length];


        for (int i = 0; i < keywords.length; i++) {
            String c = keywords[i];

            if (url1.endsWith(c)) {
                keywordsF[i] = c;
            }
        }

        return keywordsF;


    }

    //Hashing Method - made using Gemini

    public static boolean isTrustedUrl(String url) {

        String[] trustedHashes = {
                "92a1304e3db5c1d715f3f2112712535966e6f5921002ad38ac107bbec2bede67",
                "9f6ab3d90c9ebc780db79d036f3cda0e49e22bf84c49a685ba95bb9cdd27911c",
                "62789dc5c8af1194accd40524ebb0e88708ebb5bc8a8ef78f3d91588696002db",
                "0fa41192781ec2f690958d3048821e802eedd0a828de83039dea60482b1d31eb",
                "36e92d8466f2c8d732ee3e27522f06892973f562a1b02fb2495bfdf3f13e6b97",
                "4d72db2b3888f060678d1f97c662e305d469dad58167bd37fa8c39f68090a627",
                "6f990bcf4c9950c2b9f2705ad5de5b4a16c9ec9eef89ebe332564089753e47ad",
                "f1c598283fbd9fe149338c25289d050851ecaf3f2ae9d002e57c9b013dc96f35",
                "18b1a9364870f98713146ec22e2954c26d0f4e683f7dd978de93da62ef5e1c92",
                "13636806ad7a78f8d1bc5ff4fc0ecbd3a4079332c3fd01c3429e303ac3413e2a",
                "a51378bb2edb8addafdd70e7b3f02d1dd446981bed0dd69ead78569db061dfa5",
                "9b2d7d21c0fb5a0dca290e6d3efed7fdeee0940345fd0ac672ca79f652d002bb"
        };

        if (url.contains("@")) return false;
        String domain = url.toLowerCase()
                .replaceAll("^https?://(www\\.)?", "")
                .replaceAll("[/?#:].*", "");

        try {

            String saltedInput = "CFSecurityTM" + domain;
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hashBytes = digest.digest(saltedInput.getBytes(StandardCharsets.UTF_8));


            StringBuilder hexString = new StringBuilder();
            for (int x = 0; x < hashBytes.length; x++) {
                hexString.append(String.format("%02x", hashBytes[x]));
            }


            String generatedHash = hexString.toString();
            for (int i = 0; i < trustedHashes.length; i++) {
                if (trustedHashes[i].equals(generatedHash)) {
                    return true;
                }
            }

            return false;

        } catch (Exception e) {
            return false;
        }
    }

    public static int isUrlShortened(String url) {

        url = url.toLowerCase();

        // Made the slash and trailing characters optional (/?.*)
        if (url.matches(".*https?://(www\\.)?bit\\.ly(/.*)?")) {
            return 1;
        } else if (url.matches(".*https?://(www\\.)?tinyurl\\.com(/.*)?")) {
            return 2;
        } else if (url.matches(".*https?://(www\\.)?(rebrand\\.ly|rb\\.gy)(/.*)?")) {
            return 3;
        } else {
            return 0;
        }
    }

    public static boolean checkDatabase(String url) {
        String query = "SELECT url_name, dangerRating FROM url_database";

        try (Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASS);
             PreparedStatement pstmt = conn.prepareStatement(query);
             ResultSet rs = pstmt.executeQuery()) {


            while (rs.next()) {
                String dbUrlName = rs.getString("url_name");
                int dangerRating = rs.getInt("dangerRating");


                if (url.toLowerCase().contains(dbUrlName.toLowerCase()) && dangerRating > 7) {
                    return true;
                }
            }

        } catch (SQLException e) {
            System.out.println("Database error: " + e.getMessage());
        }

        return false; // No high-severity match found

    }

    public static int getDangerRating(String url) {
        String query = "SELECT url_name, dangerRating FROM url_database";
        int dangerRating = 0;

        try (Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASS);
             PreparedStatement pstmt = conn.prepareStatement(query);
             ResultSet rs = pstmt.executeQuery()) {

            // Loop through rows and match the specific URL name
            while (rs.next()) {
                String dbUrlName = rs.getString("url_name");
                if (url.toLowerCase().contains(dbUrlName.toLowerCase())) {
                    dangerRating = rs.getInt("dangerRating");
                    break; // Exit early once we find the matching record's rating!
                }
            }

        } catch (SQLException e) {
            System.out.println("Database error: " + e.getMessage());
        }

        return dangerRating;
    }


    public static boolean checkDomainAge(String url) {
        String query = "SELECT url_name, url_dateAdded FROM url_database";

        try (Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASS);
             PreparedStatement pstmt = conn.prepareStatement(query);
             ResultSet rs = pstmt.executeQuery()) {

            while (rs.next()) {
                String dbUrlName = rs.getString("url_name");

                // Check if the current row matches the URL being tested
                if (url.toLowerCase().contains(dbUrlName.toLowerCase())) {
                    // Get the SQL date and convert it to a Java LocalDate
                    java.sql.Date sqlDate = rs.getDate("url_dateAdded");
                    if (sqlDate != null) {
                        LocalDate dateAdded = sqlDate.toLocalDate();
                        LocalDate today = LocalDate.now();

                        // Calculate the difference in days between creation and today
                        long daysBetween = ChronoUnit.DAYS.between(dateAdded, today);

                        // If it was created within the last 30 days, flag it!
                        if (daysBetween <= 30 && daysBetween >= 0) {
                            return true; // Too new = Suspicious!
                        }
                    }
                }
            }

        } catch (SQLException e) {
            System.out.println("Database error: " + e.getMessage());
        }

        return false; // Older than 30 days or not found in DB
    }

    public static int getDomainAge(String url) {
        String query = "SELECT url_name, url_dateAdded FROM url_database";
        int daysBetween = 0;

        try (Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASS);
             PreparedStatement pstmt = conn.prepareStatement(query);
             ResultSet rs = pstmt.executeQuery()) {

            while (rs.next()) {
                String dbUrlName = rs.getString("url_name");

                // Check if the URL matches a record in your database
                if (url.toLowerCase().contains(dbUrlName.toLowerCase())) {
                    java.sql.Date sqlDate = rs.getDate("url_dateAdded");
                    if (sqlDate != null) {
                        LocalDate dateAdded = sqlDate.toLocalDate();
                        LocalDate today = LocalDate.now();

                        // Calculate the exact age in days
                        daysBetween = (int) ChronoUnit.DAYS.between(dateAdded, today);
                        break; // Stop searching once matched
                    }
                }
            }

        } catch (SQLException e) {
            System.out.println("Database error: " + e.getMessage());
        }

        return daysBetween;
    }

    //method built using Claude to ensure a security first mindset

    private static final int MIN_INSERT_RATING = 8;   // only "extreme" URLs are ever stored
    private static final int MAX_NAME_LENGTH = 75;    // matches url_name varchar(75)
    private static final int MAX_TLD_LENGTH = 20;     // set this to your url_tld column size

    public static boolean urlDBInsertion(String url, int dangerR) {

        if (url == null || dangerR < MIN_INSERT_RATING) {
            return false;
        }

        // Isolate the real host: strip scheme, path/query/fragment, anything before '@', the port and 'www.'
        String authority = url.trim().toLowerCase()
                .replaceAll("^https?://", "")
                .replaceAll("[/?#].*", "");

        String host = authority.substring(authority.lastIndexOf('@') + 1)
                .replaceAll(":.*", "")
                .replaceAll("^www\\.", "");

        // Only store well-formed hostnames
        if (!host.matches("[a-z0-9.-]{3," + MAX_NAME_LENGTH + "}")
                || !host.contains(".")
                || host.startsWith(".") || host.endsWith(".")
                || host.contains("..")
                || host.matches("\\d{1,3}(\\.\\d{1,3}){3}")) {   // raw IPs would substring-match other addresses
            return false;
        }

        // Never blocklist a trusted domain
        if (isTrustedUrl("https://" + host)) {
            return false;
        }

        String tld = host.substring(host.lastIndexOf('.'));
        if (tld.length() > MAX_TLD_LENGTH) {
            return false;
        }

        // Insert only if the host isn't already stored (no duplicates, no extra constraint needed)
        String sql = "INSERT INTO url_database (url_name, url_dateadded, url_tld, dangerrating) "
                + "SELECT CAST(? AS VARCHAR), CAST(? AS DATE), CAST(? AS VARCHAR), CAST(? AS INTEGER) "
                + "WHERE NOT EXISTS (SELECT 1 FROM url_database WHERE url_name = ?)";

        try (Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASS);
             PreparedStatement pstmt = conn.prepareStatement(sql)) {

            pstmt.setString(1, host);
            pstmt.setDate(2, java.sql.Date.valueOf(LocalDate.now()));
            pstmt.setString(3, tld);
            pstmt.setInt(4, dangerR);
            pstmt.setString(5, host);

            return pstmt.executeUpdate() > 0;

        } catch (SQLException e) {
            System.out.println("Could not add this URL to the database.");
            // While testing, add: System.out.println(e.getMessage());
            return false;
        }
    }

} //main CLASS

