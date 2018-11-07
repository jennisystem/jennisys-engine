from subprocess import check_output
from time import sleep

COMPARE_EXCLUDES = -3
COMPARE_LESS = -2
COMPARE_LESSEQUAL = -1
COMPARE_EQUALS = 0
COMPARE_GREATEREQUAL = 1
COMPARE_GREATER = 2
COMPARE_CONTAINS = 3
COMPARE_FAIL = 254

def writeScores( image, fixed, total, points, vulns ):
    with open( '/opt/JenniSys/ReportTemp.html', 'r' ) as i, open( '/opt/JenniSys/Report.html', 'w' ) as out:
        for l in i:
            if l.strip() == '{{vulns}}':
                for vuln in vulns:
                    out.write(vuln)
            else:
                n = l
                n = n.replace( "{{image}}", image )
                n = n.replace( "{{fixed}}", str( fixed ) )
                n = n.replace( "{{max}}", str( total ) )
                n = n.replace( "{{points}}", str( points ) )
                out.write( n )

class VulnObject:
    command = ""
    integer = False
    expected = ""
    compare = 0
    points = 0
    comment = ""
    def __init__( self, command, integer, expected, compare, points, comment ):
        self.command = command
        self.integer = integer
        self.expected = expected
        self.compare = compare
        self.points = points
        self.comment = comment
    def check( self ):
        output = check_output( self.command, shell = True ).decode( "UTF-8" )
        if self.integer:
            output = int( output )
        if self.compare == COMPARE_EXCLUDES:
            if str( output ).find( str( expected ) ) == -1:
                return ( True, self.points, self.comment )
        elif self.compare == COMPARE_LESS:
            if output < self.expected:
                return ( True, self.points, self.comment )
        elif self.compare == COMPARE_LESSEQUAL:
            if output <= self.expected:
                return ( True, self.points, self.comment )
        elif self.compare == COMPARE_EQUALS:
            if output == self.expected:
                return( True, self.points, self.comment )
        elif self.compare == COMPARE_GREATEREQUAL:
            if output >= self.expected:
                return ( True, self.points, self.comment )
        elif self.compare == COMPARE_GREATER:
            if output > self.expected:
                return ( True, self.points, self.comment )
        elif self.compare == COMPARE_CONTAINS:
            if not str( output ).find( str( expected ) ) == -1:
                return ( True, self.points, self.comment )
        return ( False, None )

vulns = []
# Vulnerabilities go here

last = 0
while True:
    vulnHTML = []
    fixed = 0
    points = 0
    for vuln in vulns:
        data = vuln.check()
        if data[0] == 1:
            points += data[ 1 ]
            fixed += 1
            vulnHTML.append( "<p>" + data[ 2 ] + " - " + str( data[ 1 ] ) + "</p>" )
    writeScores( "JenniSys Engine", fixed, len( vulns ), points, vulnHTML )
    sleep(30)
