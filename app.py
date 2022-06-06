import base64
from sqlite3 import Time
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import redirect, secure_filename

from flask import Flask, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp

from functions import login_required, error
from simpleDB import Database

import random
import time

# Create Flask Application
app = Flask(__name__)

# Connect To Database
db = Database("Database.db")





# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

def check_args(*args):
    for arg in args:
        if not arg: return False

    return True


# Home Directory
@app.route("/")
def index():

    if session.get("Organisation_ID") is not None:
        tournaments, status = db.execute("SELECT * FROM Tournaments WHERE Privacy=? OR Organisation_ID=?", ('public', session.get("Organisation_ID")))
            
    else:
        tournaments, status = db.execute("SELECT * FROM Tournaments WHERE Privacy=?", ('public',))

    if tournaments is None:
        return render_template("index.html", newMatches=[])

    tourIDs = []
    for tour in tournaments:
        tourIDs.append(tour["Tournament_ID"])

    timern = int(time.time()*1000)
    tourIDs.append(timern)

    print()
    matches, status = db.execute("SELECT * FROM Matches WHERE Tournament_ID IN (" + "?, " * (len(tourIDs)-2) + " ?) AND Time < ? ORDER BY Time DESC;", tourIDs)

    if matches is None:
        return render_template("index.html", newMatches=[])

    newMatches = []

    for match in matches:
        t1 = match["Team_One_ID"]
        t2 = match["Team_Two_ID"]
        gameID = match['Game_ID']
        tourID = match['Tournament_ID']

        Team_One = db.execute("SELECT * FROM Teams WHERE Team_ID=?", (t1,))[0][0]
        Team_Two = db.execute("SELECT * FROM Teams WHERE Team_ID=?", (t2,))[0][0]
        Tournament = db.execute("SELECT * FROM Tournaments WHERE Tournament_ID=?", (tourID,))[0][0]["Name"]
            
        Result = match['Result']
        Desc = match["Description"]
        Score = match["Score"]
        Time = match["Time"]

        if ":" in Score:
            s = Score.split(":")
            Score = s[0].strip() + " : " + s[1].strip()

        for team in [Team_One, Team_Two]:
            enc = base64.b64encode(team['Logo'])
            team['Logo'] = enc.decode('utf-8')

        newMatches.append({
            'Tournament_Name': Tournament,
            't1': Team_One,
            't2': Team_Two,
            'Score': Score,
            'Time': Time,
            'Result': Result,
        })

    return render_template("index.html", newMatches=newMatches)

# Login Page
@app.route("/login", methods=["GET", "POST"])
def login():
    session.clear()

    if request.method == "GET":
        return render_template("login.html")
    
    password = request.form.get("password")

    if not check_args(password, request.form.get("username")): return render_template("login.html", error=error(401, "Missing Password or Username"))

    # Query database for username
    rows, status = db.execute("SELECT * FROM Users WHERE Username = ?", (request.form.get("username"),))

    if rows is None:
        return render_template("login.html", error=error(401, "Incorrect Password or Username"))

    # Ensure username exists and password is correct
    if len(rows) != 1 or not check_password_hash(rows[0]["User_Password"], request.form.get("password")):

        return render_template("login.html", error=error(401, "Incorrect Password or Username"))
        # Remember which user has logged in

    session["User_ID"] = rows[0]["User_ID"]
    session["Organisation_ID"] = rows[0]["Organisation_ID"]
    return redirect("/")


@app.route("/signup", methods=["GET", "POST"])
def signUp():

    if request.method == "GET":
        Code = [{"Organisation_Code": ""}]
        if session.get("Organisation_ID") is not None:
            Code, status = db.execute("SELECT * FROM Organisations WHERE Organisation_ID=?", (session.get("Organisation_ID"),))
        session.clear()
        return render_template("signup.html", code=Code[0]["Organisation_Code"])

    username = request.form.get("username")
    password = request.form.get("password")
    organisationCode = request.form.get("organisation_code")

    if not check_args(username, password, organisationCode):
        return render_template("signup.html", error=error(401, "Missing Arguments"))

    orgRow, status = db.execute("SELECT * FROM Organisations WHERE Organisation_Code = ?", (organisationCode,))
    if orgRow is None or len(orgRow) < 1:
        return render_template("signup.html", error=error(401, "Invalid Organisation Code"))

    usernameRow, status = db.execute("SELECT * FROM Users WHERE Username=?", (username,))
    if usernameRow is not None and len(usernameRow) > 0:
        return render_template("signup.html", error=error(401, "Username Has Already Been taken"))

    hash = generate_password_hash(password)
    db.execute("INSERT INTO Users (Username, User_Password, Organisation_ID) VALUES (?, ?, ?)", (username, hash, orgRow[0]["Organisation_ID"]))

    rows, status = db.execute("SELECT * FROM Users WHERE Username = ?", (request.form.get("username"),))
    
    session.clear()
    session["User_ID"] = rows[0]["User_ID"]
    session["Organisation_ID"] = rows[0]["Organisation_ID"]

    return redirect("/")


@app.route("/registerOrg", methods=["GET", "POST"])
def registerOrg():

    if request.method == "GET":
        return render_template("registerOrg.html")

    name = request.form.get("name")

    if not check_args(name):
        return render_template("registerOrg.html", error=error(401, "Missing Arguments"))

    Row, status = db.execute("SELECT * FROM Organisations WHERE Organisation_Name=?", (name,))
    if Row is not None and len(Row) > 0:
        return render_template("registerOrg.html", error=error(401, "Name Has Already Been taken"))

    Code = random.randint(100000,999999)

    orgRows, status = db.execute("SELECT * FROM Organisations WHERE Organisation_Code=?", (Code,))

    while orgRows is not None and len(orgRows) > 0:
        Code = random.randint(100000, 999999)

    db.execute("INSERT INTO Organisations (Organisation_Name, Organisation_Code) VALUES (?, ?)", (name, Code))

    rows, status = db.execute("SELECT * FROM Organisations WHERE Organisation_Code = ?", (Code,))
    session["Organisation_ID"] = rows[0]["Organisation_ID"]

    return redirect("/signup")


@app.route("/Tournament/new", methods=["GET", "POST"])
@login_required
def createTournament():
    Types, status = db.execute("SELECT * FROM Games;")

    if request.method == "GET":
        return render_template("creator.html", types=Types)

    name = request.form.get("name").strip()
    details = request.form.get("details").strip()
    gameType = request.form.get("type").strip()
    privacy = request.form.get("privacy").lower()
    count = int(request.form.get("count"))

    if not check_args(name, details, gameType, privacy, count) or privacy not in ['private', 'public']:
        return render_template("creator.html", types=Types, error=error(401, "Missing Arguments"))

    Data = []

    for i in range(1, count + 1):
        teamName = request.form.get('team-' + str(i) + '-name')
        teamLogo = request.files['team-' + str(i) + '-logo'].read()
        teamCount = request.form.get('team-' + str(i) + '-count')

        if not check_args(teamName, teamLogo, teamCount):
            return render_template("creator.html", types=Types, error=error(402, "Missing Arguments"))

        playerData = []

        for j in range(1, int(teamCount) + 1):
            playerName = request.form.get('team-' + str(i) + '-player-' + str(j) + '-name')
            playerDetails = request.form.get('team-' + str(i) + '-player-' + str(j) + '-details')

            if not check_args(playerName, playerDetails):
                return render_template("creator.html", types=Types, error=error(403, "Missing Arguments"))

            playerData.append({"name": playerName, "details": playerDetails})
        
        Data.append({
            "name": teamName,
            "logo": teamLogo,
            "players": playerData
        })

    if db.execute("SELECT * FROM Games WHERE Game_ID=?", (gameType,))[0] is None:
        return render_template("creator.html", types=Types, error=error(401, "Invalid Arguments"))

    # Checked All Data Clean, Can now Add it to Database

    # Tournament Add
    db.execute("INSERT INTO Tournaments (Name, Organisation_ID, Privacy, Details, Game_ID) VALUES (?,?,?,?,?)", (name,session.get("Organisation_ID"), privacy, details, gameType))

    tourID = db.execute("SELECT  * FROM Tournaments WHERE Name=? AND Organisation_ID=?", (name,session.get("Organisation_ID")))[0][0]['Tournament_ID']
    # Teams Add
    for team in Data:
        db.execute("INSERT INTO Teams (Name, Game_ID, Organisation_ID, Logo, Tournament_ID, Score) VALUES (?,?,?,?,?,0)", (team['name'], gameType, session.get("Organisation_ID"), team['logo'], tourID))

        teamID = db.execute("SELECT * FROM Teams WHERE Name=? AND Organisation_ID=?", (team['name'], session.get("Organisation_ID")))[0][0]['Team_ID']
        for player in team['players']:
            db.execute("INSERT INTO Players (Name, Details, Team_ID) VALUES (?, ?, ?)", (player['name'], player['details'], teamID))

    return redirect('/')


@app.route("/Tournament")
@login_required
def Tournament():

    tourID = request.args.get('id')
    tournament = db.execute("SELECT * FROM Tournaments WHERE Tournament_ID=?", (tourID,))[0][0]

    matches, status = db.execute("SELECT * FROM Matches WHERE Tournament_ID=? ORDER BY Time DESC;", (tourID))

    if not check_args(matches):
        return render_template('tournament.html', Tournament=tournament, newMatches=[])

    newMatches = []

    for match in matches:
        t1 = match["Team_One_ID"]
        t2 = match["Team_Two_ID"]
        tourID = match['Tournament_ID']

        Team_One = db.execute("SELECT * FROM Teams WHERE Team_ID=?", (t1,))[0][0]
        Team_Two = db.execute("SELECT * FROM Teams WHERE Team_ID=?", (t2,))[0][0]
        Tournament = db.execute("SELECT * FROM Tournaments WHERE Tournament_ID=?", (tourID,))[0][0]["Name"]
            
        Result = match['Result']
        Desc = match["Description"]
        Score = match["Score"]
        Time = match["Time"]

        if ":" in Score:
            s = Score.split(":")
            Score = s[0].strip() + " : " + s[1].strip()

        for team in [Team_One, Team_Two]:
            enc = base64.b64encode(team['Logo'])
            team['Logo'] = enc.decode('utf-8')

        newMatches.append({
            'Tournament_Name': Tournament,
            't1': Team_One,
            't2': Team_Two,
            'Score': Score,
            'Time': Time,
            'Result': Result,
        })

    
    teams, status = db.execute("SELECT * FROM Teams WHERE Tournament_ID=?", (tourID,))

    for team in teams:
        enc = base64.b64encode(team['Logo'])
        team['Logo'] = enc.decode('utf-8')

        matches = db.execute("SELECT * FROM Matches WHERE Team_One_ID=? OR Team_Two_ID=?", (team['Team_ID'], team['Team_ID']))[0]

        team['Wins'] = 0
        team['Losses'] = 0
        team['Draws'] = 0
        if matches is None:
            team['matchesPlayed'] = 0
            continue
        team['matchesPlayed'] = len(matches)
        for match in matches:
            if match['Result'][0:len(team['Name']) + 1] == team["Name"] + " ":
                team['Wins'] += 1
            elif match["Result"] == "Draw":
                team['Draws'] += 1
            else:
                team['Losses'] += 1

    teams = sorted(teams, key=lambda team: team['Score'], reverse=True)

    return render_template('tournament.html', Tournament=tournament, newMatches=newMatches, teamList=teams)


@app.route("/Organisation")
@login_required
def org():

    tournaments, status = db.execute("SELECT * FROM Tournaments INNER JOIN Games ON Tournaments.Game_ID=Games.Game_ID WHERE Organisation_ID=?;", (session.get("Organisation_ID"),))

    if not check_args(tournaments):
        return render_template('organisation.html', Tournaments=[])
    return render_template('organisation.html', Tournaments=tournaments)


@app.route("/Match/new", methods=["GET", "POST"])
@login_required
def newMatch():

    if request.method == "GET":
        teamsList, status = db.execute('SELECT * FROM Teams WHERE Tournament_ID=?', (request.args.get('id'),))

        for team in teamsList:
            enc = base64.b64encode(team['Logo'])
            team['Logo'] = enc.decode('utf-8')

        return render_template('newMatch.html', teamsList=teamsList, T_ID=request.args.get('id'))

    t1 = request.form.get('Team_One').split('~')[1]
    t2 = request.form.get('Team_Two').split('~')[1]
    score = request.form.get('score')
    results = request.form.get('results')
    description = request.form.get('description')
    Tid = request.form.get('id')

    if results[0:len(request.form.get('Team_One').split('~')[0]) + 1] == request.form.get('Team_One').split('~')[0] + " ":
        tscore = db.execute("SELECT * FROM Teams WHERE Team_ID=?", (t1,))[0][0]["Score"] + 3
        db.execute('UPDATE Teams SET Score=? WHERE Team_ID=?', (tscore, t1))
    elif results == "Draw":
        tscore = db.execute("SELECT * FROM Teams WHERE Team_ID=?", (t1,))[0][0]["Score"] + 1
        db.execute('UPDATE Teams SET Score=? WHERE Team_ID=?', (tscore, t1))
        tscore = db.execute("SELECT * FROM Teams WHERE Team_ID=?", (t2,))[0][0]["Score"] + 1
        db.execute('UPDATE Teams SET Score=? WHERE Team_ID=?', (tscore, t2))
    else:
        tscore = db.execute("SELECT * FROM Teams WHERE Team_ID=?", (t2,))[0][0]["Score"] + 3
        db.execute('UPDATE Teams SET Score=? WHERE Team_ID=?', (tscore, t2))
    


    if not check_args(t1, t2, score, results, description):
        teamsList, status = db.execute('SELECT * FROM Teams WHERE Tournament_ID=?', (Tid,))

        for team in teamsList:
            enc = base64.b64encode(team['Logo'])
            team['Logo'] = enc.decode('utf-8')

        return render_template('newMatch.html', teamsList=teamsList, error=error("Missing Arguments", 401))

    Gid = db.execute("SELECT * FROM Tournaments WHERE Tournament_ID=?", (Tid,))[0][0]['Tournament_ID']
    db.execute("INSERT INTO Matches (Tournament_ID, Team_One_ID, Team_Two_ID, Game_ID, Result, Description, Time, Score) VALUES (?,?,?,?,?,?,?,?)", (Tid, t1, t2, Gid, results, description, int(time.time()*1000), score))

    return redirect('/')

# Run The Application
if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=True)
