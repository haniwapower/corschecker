import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.UnknownHostException;
import java.util.List;
import java.util.Map;
import java.util.Scanner;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class CORSChecker {

	public static void main(String[] args) {

		try
		{
			System.out.print(System.lineSeparator()
					+ "#########################################################################"
					+ System.lineSeparator());
			System.out.print("#    _____ ____  _____   _____    _____ _               _               #"
					+ System.lineSeparator());
			System.out.print("#   / ____/ __ \\|  __ \\ / ____|  / ____| |             | |              #"
					+ System.lineSeparator());
			System.out.print("#  | |   | |  | | |__) | (___   | |    | |__   ___  ___| | _____ _ __   #"
					+ System.lineSeparator());
			System.out.print("#  | |   | |  | |  _  / \\___ \\  | |    | '_ \\ / _ \\/ __| |/ / _ \\ '__|  #"
					+ System.lineSeparator());
			System.out.print("#  | |___| |__| | | \\ \\ ____) | | |____| | | |  __/ (__|   <  __/ |     #"
					+ System.lineSeparator());
			System.out.print("#   \\_____\\____/|_|  \\_\\_____/   \\_____|_| |_|\\___|\\___|_|\\_\\___|_|     #"
					+ System.lineSeparator());
			System.out.print("#                                                                       #"
					+ System.lineSeparator());
			System.out.print("#  By: Milad Khoshdel                  Blog: https://blog.regux.com     #"
					+ System.lineSeparator());
			System.out.print("#  Email: Miladkhoshdel@gmail.com                                       #"
					+ System.lineSeparator());
			System.out.print("#                                                                       #"
					+ System.lineSeparator());
			System.out.print("#########################################################################"
					+ System.lineSeparator()
					+ System.lineSeparator());

			Pattern p = Pattern.compile("(http|https):\\/\\/[0-9A-Za-z\\.-]*\\.[0-9a-zA-Z]{2,10}.*");
			System.setProperty("sun.net.http.allowRestrictedHeaders", "true");
			String domainname;
			String origin = "http://test-site-example.com";
			Scanner sc = new Scanner(System.in);
			System.out.println("Enter a URL (Exapmle: https://foo.bar): ");

			String[] inputLines = sc.nextLine().split(" ");
			domainname = inputLines[0];
			domainname = domainname.replaceAll("\\s+", "");

			URL url = null;
			if (domainname.contains("http")) {
				url = new URL(domainname);
			} else {
				url = new URL("http://" + domainname);
			}
			Matcher m = p.matcher(url.toString());
			while (!m.matches())
			{

				System.out.print(url.toString() + " is invalid. Please Enter a Valid URL (Exapmle: https://foo.bar): ");
				inputLines = sc.nextLine().split(" ");
				domainname = inputLines[0];
				if (domainname.contains("http")) {
					url = new URL(domainname);
				} else {
					url = new URL("http://" + domainname);
				}
				m = p.matcher(url.toString());
			}

			System.out.println("");
			System.out.println("");
			System.out.print("***** Request from origin that cannot access the resource ***** ");
			new CORSChecker().sendRequest(url, origin, false);

			if (inputLines.length > 1) {
				System.out.println("");
				System.out.println("");
				System.out.print("***** Requests from origin that can access resources ***** ");
				String accessableOrigin = inputLines[1];
				new CORSChecker().sendRequest(url, accessableOrigin, true);
			}
		} catch (Exception e)
		{
			e.printStackTrace();
			System.out.print(System.lineSeparator() + " [-] Some Error Happened.");
		}

	}

	public void sendRequest(URL url, String origin, boolean isAccessableOrigin) {
		try {
			Scanner sc = new Scanner(System.in);
			HttpURLConnection conn = (HttpURLConnection)url.openConnection();

			conn.setRequestProperty("User-Agent",
					"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.103 Safari/537.36");
			conn.setRequestProperty("Origin", origin);

			System.out.print(System.lineSeparator()
					+ "Complete Response Header:"
					+ System.lineSeparator()
					+ System.lineSeparator());
			System.out.print(System.lineSeparator() + "[+] Your URL: " + url);
			System.out.print(System.lineSeparator() + "[+] Origin Method Set to " + conn.getRequestProperty("Origin"));
			System.out.print(System.lineSeparator()
					+ "[+] Getting Response Code: "
					+ conn.getResponseCode()
					+ System.lineSeparator());

			Map<String, List<String>> map = conn.getHeaderFields();
			for (Map.Entry<String, List<String>> entry : map.entrySet()) {
				System.out.println("[+] " + entry.getKey() + ":" + entry.getValue());
			}
			BufferedReader in = new BufferedReader(
					new InputStreamReader(conn.getInputStream()));
			String inputLine;
			StringBuffer content = new StringBuffer();
			while ((inputLine = in.readLine()) != null) {
				content.append(inputLine);
			}
			in.close();
			conn.disconnect();

			System.out.print("----------------------------------------");
			System.out.print(System.lineSeparator() + "[+] Status: " + System.lineSeparator());

			if (conn.getHeaderField("Access-Control-Allow-Origin") != null)
			{
				if (conn.getHeaderField("Access-Control-Allow-Origin").contains("*"))
				{
					System.out.println(" [-] Vurnerable!   --->    "
							+ "Access-Control-Allow-Origin: "
							+ (conn.getHeaderField("Access-Control-Allow-Origin")));
				}
				else if ((conn.getHeaderField("Access-Control-Allow-Origin").contains(origin)))
				{
					if (isAccessableOrigin) {
						System.out.println("\" [-] Access-Control-Allow-Origin: "
								+ (conn.getHeaderField("Access-Control-Allow-Origin")));
					} else {
						System.out.println(" [-] Vurnerable!   --->    "
								+ "Access-Control-Allow-Origin: "
								+ (conn.getHeaderField("Access-Control-Allow-Origin")));
					}
				}
				else
				{
					if (isAccessableOrigin) {
						System.out.println(" [-] Warning!      --->     Not Vulnerable");
					} else {
						System.out.println(" [-] Not Vulnerable");

					}
				}

				if (conn.getHeaderField("Access-Control-Allow-Credentials") != null)
				{
					if (conn.getHeaderField("Access-Control-Allow-Credentials").contains("true"))
					{
						System.out.println(" [-] Warning!      --->    "
								+ "Access-Control-Allow-Credentials: "
								+ (conn.getHeaderField("Access-Control-Allow-Origin")));
					}
				}

				sc.close();
			}
			else
			{
				if (isAccessableOrigin) {
					System.out.println(" [-] Warning!      --->    There is no Access-Control-Allow-Origin Header.");
				} else {
					System.out.println(" [-] There is no Access-Control-Allow-Origin Header.");
				}
			}
		} catch (UnknownHostException exception)
		{
			System.out
					.print(System.lineSeparator()
							+ " [-] Error: Host is Invalid. Please Check your URL and make sure that you are connected to the internet.");
		} catch (Exception e)
		{
			e.printStackTrace();
			System.out.print(System.lineSeparator() + " [-] Some Error Happened.");
		}
	}

}
