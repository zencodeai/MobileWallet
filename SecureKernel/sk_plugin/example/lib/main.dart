import 'package:flutter/material.dart';

import 'package:sk_plugin/sk_plugin.dart' as sk_plugin;

void main() => runApp(const MyApp());

class MyApp extends StatelessWidget {

  const MyApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Mobile Wallet PoT',
      theme: ThemeData(
        primarySwatch: Colors.blue,
      ),
      home: const MyHomePage(),
    );
  }
}

class MyHomePage extends StatefulWidget {

  const MyHomePage({super.key});

  @override
  _MyHomePageState createState() => _MyHomePageState();
}

class _MyHomePageState extends State<MyHomePage> {
  List<String> logs = [];
  final ScrollController _scrollController = ScrollController();

  void _handlePress(String action) {
    setState(() {
      logs.add('Button "$action" was pressed at ${DateTime.now()}');
    });

    // Scrolls to the bottom of the ListView to display the latest entry
    _scrollController.animateTo(
      _scrollController.position.maxScrollExtent,
      duration: const Duration(milliseconds: 300),
      curve: Curves.easeOut,
    );
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('Mobile Wallet PoT'),
      ),
      body: Center(
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: <Widget>[
              Expanded(
              child: ListView.builder(
                controller: _scrollController,
                itemCount: logs.length,
                itemBuilder: (BuildContext context, int index) {
                  return ListTile(
                    title: Text(logs[index]),
                  );
                },
              ),
            ),
            ElevatedButton(
              child: const Text('Provision'),
              onPressed: () => _handlePress('Provision'),
            ),
            const SizedBox(height: 16),
            ElevatedButton(
              child: const Text('Initialize'),
              onPressed: () => _handlePress('Initialize'),
            ),
            const SizedBox(height: 16),
            ElevatedButton(
              child: const Text('Online TX'),
              onPressed: () => _handlePress('Online TX'),
            ),
            const SizedBox(height: 16),
            ElevatedButton(
              child: const Text('Status'),
              onPressed: () => _handlePress('Status'),
            ),
            const SizedBox(height: 32),
          ],
        ),
      ),
    );
  }
}
