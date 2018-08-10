Add-Type -AssemblyName System.speech
$tts = New-Object System.Speech.Synthesis.SpeechSynthesizer
$Phrase = '
<speak version="1.0" xmlns="http://www.w3.org/2001/10/synthesis" xml:lang="en-US">
 <voice xml:lang="en-GB">
  <prosody rate="0.7" pitch="+20st">
   <p>This was a triumph!<break time="700ms"/>
I''m making a note here <break time="25ms"/>"Huge success"
<break time="775ms"/>
<prosody rate="0.55">It''s hard<break time="25ms"/> to overstate<break time="25ms"/> my satisfaction</prosody>.
<break time="800ms"/>
Aperture Science.
<break time="500ms"/>

We do what we must <break time="50ms"/>
because <break time="100ms"/> we can.
<prosody rate="0.4">For the good of all of us</prosody><break time="100ms"/>
<prosody rate="1.05">Except the ones who are dead</prosody>, <break time="50ms"/>

<prosody rate="0.8">But there''s no sense crying over every<break time="25ms"/> mistake</prosody><break time="150ms"/>

<prosody rate="0.8">You just keep on trying ''til you run out of cake</prosody><break time="200ms"/>

<prosody rate="0.80">And the science gets done</prosody><break time="25ms"/>
<prosody rate="0.70">and you make a neat gun</prosody><break time="25ms"/>
<prosody rate="0.80">for the people who</prosody> <prosody rate="0.5">are <break time="25ms"/>still alive.</prosody>
<break time="3300ms"/>

I''m not even angry<break time="1775ms"/>
I''m being so <break time="100ms"/> sincere <break time="100ms"/> right now<break time="1450ms"/>
<prosody rate="0.6">Even though<break time="200ms"/> you broke my heart</prosody><break time="200ms"/> and killed me<break time="1450ms"/>
<prosody rate="1.05">And tore me to</prosody> pieces. <break time="600ms"/>
And threw every piece <break time="50ms"/> <prosody rate="0.4">into</prosody><break time="50ms"/> a fire.
<break time="425ms"/>
<prosody rate="0.6">As they burned<break time="50ms"/></prosody> <prosody rate="0.75">it hurt because</prosody><break time="40ms"/>
<prosody rate="0.85">I was so happy</prosody> for you<break time="200ms"/>

<prosody rate="0.70">Now these points of data</prosody>
Make a beautiful <prosody rate="0.7">line</prosody><break time="125ms"/>
And we''re <prosody rate="0.5">out of beta</prosody>
<prosody rate="0.80">We''re releasing on time</prosody> <break time="125ms"/>
<prosody rate="0.90">So I''m GLaD I got burned</prosody><break time="25ms"/>
<prosody rate="0.90">Think of all the things we</prosody> learnt
for the people who are <break time="25ms"/>still <prosody rate="0.4">alive</prosody>
<break time="4400ms"/>

<prosody volume="-20%">
Go head and leave me.<break time="600ms"/>
I think I''d prefer <break time="50ms"/> to stay <break time="200ms"/> inside.<break time="250ms"/>
<prosody rate="0.62">Maybe you''ll<break time="125ms"/> find someone else</prosody> <break time="230ms"/> to help you.<break time="700ms"/>
</prosody>

Maybe Black Mesa? <break time="700ms"/>
That was a joke <break time="100ms"/> Ha Ha <break time="100ms"/> Fat chance!
<break time="250ms"/>
<prosody rate="0.5">Anyway</prosody><break time="50ms"/> this <prosody rate="0.6">cake is great</prosody><break time="25ms"/>
<prosody rate="1.02">It''s so delicious and moist</prosody> <break time="250ms"/>

<prosody rate="0.8">Look at me<break time="50ms"/> still talking when there''s science to do</prosody><break time="250ms"/>
When I look <prosody rate="0.6">out there</prosody> <prosody rate="1.02">it makes me GLaD I''m not you</prosody><break time="225ms"/>

<prosody rate="1.02">I''ve experiments</prosody> to run<break time="150ms"/>
<prosody rate="1.02">there is research to be done </prosody><break time="250ms"/>
<prosody rate="1.00">On the people who are</prosody><break time="250ms"/>still alive<break time="900ms"/>
<prosody rate="1.05">And believe me<break time="50ms"/> I am</prosody> <break time="50ms"/>still alive<break time="750ms"/>
<prosody rate="1.05">I''m doing science</prosody><break time="25ms"/> and I''m <break time="40ms"/>still alive<break time="700ms"/>
<prosody rate="1.1">I feel fantastic</prosody><break time="25ms"/> and I''m <break time="40ms"/>still alive<break time="650ms"/>
<prosody rate="1.05">While you''re dying</prosody><break time="25ms"/> I''ll be <break time="40ms"/>still alive<break time="650ms"/>
<prosody rate="1.00">And when you''re dead <break time="25ms"/>I will be</prosody> <break time="25ms"/>still alive
<break time="560ms"/>
Still alive
<break time="560ms"/>
Still alive.
</p>
  </prosody>
 </voice>
</speak>
'
$tts.SpeakSsml($Phrase)