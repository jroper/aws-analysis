import java.io.File
import java.nio.file.Files
import java.util.Date

import scala.sys.process._
import play.api.libs.json._
import play.api.libs.functional.syntax._

import scala.annotation.tailrec

object Analyse {

  val dataDir = new File("./data")
  dataDir.mkdirs()
  def regionDir(region: String): File = {
    val regionDir = new File(dataDir, region)
    regionDir.mkdirs()
    regionDir
  }
  def eventsFile(region: String, page: Int): File = {
    new File(regionDir(region), s"events-$page.json")
  }
  val regions = discoverRegions()

  val allEvents = loadAllEvents()

  def summarise(region: String, events: Seq[AwsEvent]) = {
    println(s"Summary for $region")
    println(s"===")
    println(s"Total events: ${events.size}")

    val byType = events.groupBy(_.eventName)
    println(s"Total event types: ${byType.size}")
    println(s"Summary of types:")
    byType.foreach {
      case (t, events) =>
        println(s"$t: ${events.size}")
    }
    println()
  }

  def loadAllEvents(): Seq[(String, Seq[AwsEvent])] = {
    regions.map { region =>
      region -> loadEvents(region)
    }
  }

  @tailrec
  def loadEvents(region: String, sofar: Seq[AwsEvent] = Vector.empty, page: Int = 1): Seq[AwsEvent] = {
    val file = eventsFile(region, page)
    if (!file.exists()) {
      sofar
    } else {
      val bytes = Files.readAllBytes(file.toPath)
      val events = Json.parse(bytes).as[Vector[AwsEvent]]
      loadEvents(region, sofar ++ events, page + 1)
    }
  }

  def downloadAllEvents(): Unit = {
    regions.foreach { region =>
      downloadEvents(region)
    }
  }

  def discoverRegions(): Seq[String] = {
    Json.parse("aws ec2 describe-regions --query Regions[*].[RegionName]".!!)
      .as[JsArray].value.flatMap(_.as[Seq[String]])
  }

  @tailrec
  def downloadEvents(region: String, nextToken: Option[String] = None, page: Int = 1): Unit = {
    val command = Seq("aws", "cloudtrail", "lookup-events", "--region", region, "--max-results", "50") ++
      nextToken.fold(Seq.empty[String])(token => Seq("--next-token", token))

    print(s"Downloading page $page of events from $region...")

    val jsonStr = command.!!
    val json = Json.parse(jsonStr)

    val events = (json \ "Events").asOpt[JsArray].getOrElse(JsArray.empty)
    println(s" ${events.value.size} events loaded.")

    val file = eventsFile(region, page)
    Files.write(file.toPath, Json.toBytes(events))

    val nextNextToken = (json \ "NextToken").asOpt[String]

    nextNextToken match {
      case None => ()
      case Some(_) => downloadEvents(region, nextNextToken, page + 1)
    }
  }

}

case class AwsEvent(
  eventId: String,
  username: String,
  eventTime: Date,
  cloudTrailEvent: JsValue,
  eventName: String,
  resources: Seq[AwsResources]
)

object AwsEvent {
  implicit val reads: Reads[AwsEvent] = (
    (__ \ "EventId").read[String] and
    (__ \ "Username").read[String] and
    (__ \ "EventTime").read[Long] and
    (__ \ "CloudTrailEvent").read[String] and
    (__ \ "EventName").read[String] and
    (__ \ "Resources").read[Seq[AwsResources]]
  ).apply { (eventId, username, eventTime, cloudTrailEvent, eventName, resources) =>
    AwsEvent(eventId, username, new Date(eventTime), Json.parse(cloudTrailEvent), eventName, resources)
  }
}

case class AwsResources(
  ResourceType: String,
  ResourceName: String
)

object AwsResources {
  implicit val reads: Reads[AwsResources] = (
    (__ \ "ResourceType").read[String] and
    (__ \ "ResourceName").read[String]
  ).apply(AwsResources.apply _)
}