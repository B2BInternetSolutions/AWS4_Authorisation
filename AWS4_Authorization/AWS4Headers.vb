Imports System.Net
Imports System.Security.Cryptography
Imports System.Globalization
Imports System.Text


Namespace AWS_Security
    Public Class AWS_Credentials

        Public Shared Function AddAWS4AuthorizationHeader(
                                                        ByVal Request As HttpWebRequest,
                                                        ByVal RequestBody As Object,
                                                        ByVal AWSKey As String,
                                                        ByVal AWSSecretKey As String,
                                                        Optional ByVal AWSRegion As String = "eu-west-1",
                                                        Optional ByVal AWSService As String = "execute-api",
                                                        Optional ByVal MinimalSign As Boolean = True) As HttpWebRequest

            ' See http://docs.aws.amazon.com/general/latest/gr/sigv4-create-canonical-request.html 
            ' Step 1 Generate Canonical Request
            'Note assumes Request is already correctly URL encoded

            'Create a hasher for later use
            Dim Hasher As System.Security.Cryptography.SHA256 = System.Security.Cryptography.SHA256.Create()

            'Hash the Body
            Dim BodyBytes As Byte()
            Dim BodyEncoding As New Text.UTF8Encoding()
            ' is the body a string?
            Select Case RequestBody.GetType()
                Case GetType(String)
                    BodyBytes = BodyEncoding.GetBytes(RequestBody)

                Case GetType(Byte())
                    BodyBytes = RequestBody
                Case Else
                    Throw New ArgumentException("Body must be 'String' or 'Byte()'")

            End Select
            Dim ContentLength As Integer = BodyBytes.Length



            'Canonical Method

            Dim CanonicalRequest As String = Request.Method & vbLf

            'Canonical URI
            If String.IsNullOrWhiteSpace(Request.RequestUri.AbsolutePath) Then
                CanonicalRequest = CanonicalRequest & "/" & vbLf
            Else
                CanonicalRequest = CanonicalRequest & Request.RequestUri.AbsolutePath & vbLf
            End If

            'Canonical Query

            If Not String.IsNullOrWhiteSpace(Request.RequestUri.Query) Then
                Dim QPsRaw As New Specialized.NameValueCollection
                QPsRaw = Web.HttpUtility.ParseQueryString(Request.RequestUri.Query)
                Dim QPNames As String() = QPsRaw.AllKeys
                Array.Sort(QPNames, StringComparer.Ordinal)
                For pi As Integer = 0 To QPNames.Length - 1
                    If Not String.IsNullOrWhiteSpace(QPsRaw.Item(QPNames(pi))) Then
                        CanonicalRequest = CanonicalRequest & QPNames(pi) & "=" & QPsRaw.Item(QPNames(pi))
                    Else
                        CanonicalRequest = CanonicalRequest & QPNames(pi) & "="
                    End If
                    If pi < QPNames.Length - 1 Then CanonicalRequest = CanonicalRequest & "&"
                Next
            End If
            CanonicalRequest = CanonicalRequest & vbLf

            'Canonical Headers
            Dim newHeaders As New WebHeaderCollection
            newHeaders = Request.Headers
            'Note that name value collections like WebheaderCollection are referential therefore a change to newHeaders automatcially updates Request.Headers

            Dim DateString As String = ""
            Dim HostString = "unknown"

            'Make sure there are host and x-amz-date values and remove any authorization header as it will be replaced
            If Not IsNothing(newHeaders(HttpRequestHeader.Authorization)) Then
                newHeaders.Remove(HttpRequestHeader.Authorization)
            End If
            For kn As Integer = 0 To newHeaders.AllKeys.Length - 1
                If LCase(newHeaders.Keys(kn)) = "x-amz-date" Then
                    newHeaders.Item(newHeaders.Keys(kn)) = DateString
                End If
                If LCase(newHeaders.Keys(kn)) = "host" Then
                    HostString = newHeaders.Item(newHeaders.Keys(kn))
                End If
                If LCase(newHeaders.Keys(kn)) = "content-length" Then
                    ContentLength = CInt(newHeaders.Item(newHeaders.Keys(kn)))
                End If
            Next

            If DateString = "" Then
                DateString = DateTime.UtcNow.ToString("yyyyMMdd'T'HHmmss'Z'")
                newHeaders.Add("X-Amz-Date", DateString)
            End If
            If HostString = "unknown" Then
                HostString = Request.RequestUri.DnsSafeHost
                'newHeaders.Add("Host", Request.RequestUri.DnsSafeHost)
            End If

            Dim hdrNames As String() = newHeaders.AllKeys
            Dim SignedHeaders As String = ""

            'If only only Using host And datetime To sign Then no need To sort

            If MinimalSign Then
                CanonicalRequest = CanonicalRequest & "host:" & HostString & vbLf & "x-amz-date:" & DateString & vbLf
                SignedHeaders = "host;x-amz-date"

            Else
                'use all headers
                Array.Sort(hdrNames, StringComparer.OrdinalIgnoreCase)
                For hi As Integer = 0 To hdrNames.Length - 1
                    CanonicalRequest = CanonicalRequest & LCase(hdrNames(hi)) & ":" & System.Text.RegularExpressions.Regex.Replace(Trim(newHeaders.Item(hdrNames(hi))), "\s+", " ") & vbLf
                Next

                'Signed headers

                For shi As Integer = 0 To hdrNames.Length - 1
                    SignedHeaders = SignedHeaders & LCase(hdrNames(shi))
                    If shi < hdrNames.Length - 1 Then SignedHeaders = SignedHeaders & ";"
                Next


            End If

            CanonicalRequest = CanonicalRequest & vbLf & SignedHeaders & vbLf

            Dim HashedBodyBytes() As Byte = Hasher.ComputeHash(BodyBytes)
            CanonicalRequest = CanonicalRequest & ByteArrayToHex(HashedBodyBytes)
            Dim HashedCanonicalRequest = ByteArrayToHex(Hasher.ComputeHash(BodyEncoding.GetBytes(CanonicalRequest)))

            'Step 1 completed we and we have the canonical request. Now step 2
            'Generate the string to sign
            Dim CredentialScope As String = Left(DateString, 8) & "/" & AWSRegion & "/" & AWSService & "/aws4_request"
            Dim StringToSign As String = "AWS4-HMAC-SHA256" & vbLf & DateString & vbLf & CredentialScope & vbLf & HashedCanonicalRequest

            'We have now completed step 2 - now on to step 3



            Dim kSecret As Byte() = Text.Encoding.UTF8.GetBytes(("AWS4" & AWSSecretKey).ToCharArray())
            Dim kdate As Byte() = HMAC(Left(DateString, 8).ToCharArray(), kSecret)
            Dim kRegion As Byte() = HMAC(AWSRegion.ToCharArray, kdate)
            Dim kService As Byte() = HMAC(AWSService.ToCharArray, kRegion)
            Dim kSigning As Byte() = HMAC("aws4_request".ToCharArray, kService)

            Dim signature As String = ByteArrayToHex(HMAC(StringToSign.ToCharArray, kSigning))

            'Step 3 complete - now on to step 4

            Request.Headers.Add(HttpRequestHeader.Authorization, "AWS4-HMAC-SHA256 Credential=" & AWSKey & "/" & CredentialScope & ", SignedHeaders=" & SignedHeaders & ", Signature=" & signature)
            Dim returnedRequest As HttpWebRequest = Request
            returnedRequest.ServicePoint.Expect100Continue = False
            'Request.Headers = newHeaders

            Return Request

        End Function

        Private Shared Function HMAC(data As String, key As Byte()) As Byte()
            Dim kha As KeyedHashAlgorithm = KeyedHashAlgorithm.Create("HMACSHA256")
            kha.Key = key
            Return kha.ComputeHash(Text.Encoding.UTF8.GetBytes(data))
        End Function

        Private Shared Function ByteArrayToHex(ByVal ByteArray As Byte()) As String
            Dim hexString As String = ""
            Dim hexChar As String = ""
            For Each b As Byte In ByteArray
                hexChar = Hex(b)
                If hexChar.Length = 1 Then hexChar = "0" & hexChar
                hexString = hexString & LCase(hexChar)
            Next
            Return hexString
        End Function

    End Class
End Namespace

