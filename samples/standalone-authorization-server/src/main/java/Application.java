import org.apache.catalina.LifecycleException;
import org.apache.catalina.startup.Tomcat;

import java.io.File;
import java.util.Scanner;

public class Application {

	public static void main(String[] args) throws Exception {
		Tomcat tomcat = new Tomcat();
		tomcat.setPort(8080);
		tomcat.getHost().setAppBase(".");
		tomcat.addWebapp("", ".");
//		tomcat.getConnector();
		tomcat.start();
		// TODO: here
		exitOnKeypress();
		tomcat.stop();
	}

	private static void exitOnKeypress() {
		System.out.println("Press Enter to exit");
		Scanner scanner = new Scanner(System.in);
		scanner.nextLine();
		System.out.println("Bye bye 👋");
	}
}
